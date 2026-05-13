# LMbox Bridge — procédure d'installation pour le RSSI

**Temps prévu : 30 minutes — une seule fois par client, plus jamais
ensuite pour les boxes qu'on ajoute après.**

Document destiné au RSSI / DSI / ingénieur sécurité côté client qui
provisionne la VM de la DMZ. Pas besoin d'être familier de LMbox.

---

## Ce qu'on demande de vous

| Ressource | Détail |
|---|---|
| 1 VM Linux dans la DMZ | 4 GB RAM, 2 vCPU, 10 GB disque — Ubuntu 22.04+ / RHEL 9+ / Debian 12+ |
| 1 règle firewall sortante | `Bridge → app.lmbox.eu:443` en TLS — la SEULE règle dont on a besoin |
| Pas de règle entrante | Les LMbox boxes sur le LAN parlent au Bridge via le LAN, pas via Internet |
| 30 minutes | Pour exécuter les 5 étapes ci-dessous |

**Ce qu'on NE demande PAS :**
- Pas d'accès root au reste du SI
- Pas d'ouverture entrante depuis Internet
- Pas de modification de votre AD / Okta / SCCM
- Pas de changement aux règles existantes

---

## Étape 1 — Provisionner la VM

```
hostname:   bridge-lmbox.<your-domain>
RAM:        4 GB
vCPU:       2
disque:     10 GB
réseau:     DMZ, accès sortant uniquement vers Internet
OS:         Ubuntu 22.04 LTS (recommandé)
```

Aucun port entrant ouvert depuis Internet. Le seul flux entrant est
*depuis le LAN client* sur le port 8443/tcp, autorisé via votre
firewall interne classique.

## Étape 2 — Ouvrir 1 règle firewall sortante

```
SOURCE        → DESTINATION       → PORT  → PROTO
Bridge VM IP  → *.lmbox.eu         → 443   → TCP (TLS)
```

C'est tout. Aucune autre règle. Si votre firewall demande des
adresses IP plutôt que des FQDN, contactez-nous — nous publions la
liste IP des endpoints LMbox cloud à jour dans le portail partenaire.

## Étape 3 — Installer le binaire

```bash
# Récupérer la release signée (signature GPG vérifiée)
curl -sLO https://github.com/rlacotte/lmbox-bridge/releases/download/v0.1.0/lmbox-bridge-linux-amd64
curl -sLO https://github.com/rlacotte/lmbox-bridge/releases/download/v0.1.0/lmbox-bridge-linux-amd64.sig

# Vérifier la signature (clé GPG LMbox importée depuis keybase.io/lmbox)
gpg --verify lmbox-bridge-linux-amd64.sig lmbox-bridge-linux-amd64

# Installer
sudo install -m 0755 lmbox-bridge-linux-amd64 /usr/local/bin/lmbox-bridge
```

## Étape 4 — Configurer

Le **kit d'enrôlement client** vous a été remis par votre interlocuteur
LMbox (typiquement votre intégrateur Sopra / Inetum / Magellan).
Il contient :

- `bridge-server.crt` + `bridge-server.key` — cert présenté aux boxes
- `bridge-out.crt` + `bridge-out.key` — cert présenté au cloud LMbox
- `box-ca.pem` — CA qui a signé les certs clients des boxes
- `config.yaml` — configuration pré-renseignée avec votre `genesis`

Déployez ces fichiers :

```bash
sudo mkdir -p /etc/lmbox-bridge/certs /var/lib/lmbox-bridge
sudo cp bridge-server.* bridge-out.* box-ca.pem /etc/lmbox-bridge/certs/
sudo cp config.yaml /etc/lmbox-bridge/
sudo chmod 600 /etc/lmbox-bridge/certs/*.key
sudo chown -R root:root /etc/lmbox-bridge
```

## Étape 5 — Démarrer

```bash
sudo cp deploy/systemd/lmbox-bridge.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now lmbox-bridge
sudo systemctl status lmbox-bridge   # doit afficher "active (running)"
```

Vérifier l'écoute :

```bash
sudo ss -tlnp | grep 8443    # mTLS port pour les boxes
sudo ss -tlnp | grep 9090    # métriques (localhost uniquement)
```

Tester la connectivité sortante :

```bash
curl -s http://127.0.0.1:9090/readyz | jq
# {"ready": true, "upstream": true, "crl": true, ...}
```

---

## C'est tout

Toute box LMbox future installée chez vous parlera à ce Bridge sans
aucune action de votre part. Le boîtier est livré pré-flashé avec
l'adresse de votre Bridge ; au premier boot il enrôle son cert auprès
de la CA, et il commence à pousser ses heartbeats à travers la VM.

**Vous ne devriez plus jamais avoir à modifier votre firewall pour LMbox.**

---

## Surveillance recommandée

### Métriques à scraper avec votre Prometheus

```yaml
- job_name: lmbox-bridge
  static_configs:
    - targets: ['bridge-lmbox.your-domain:9090']
```

Métriques utiles :

| Métrique | Alerte |
|---|---|
| `lmbox_bridge_active_boxes` | < votre nombre de boxes installées pendant > 5 min |
| `lmbox_bridge_denied_total{reason="auth"}` | > 0 → cert invalide ou tentative d'intrusion |
| `lmbox_bridge_upstream_errors_total` | > 5 en 5 min → problème connectivité cloud |
| `rate(lmbox_bridge_requests_total[5m])` | > 100/s — anomalie de volume |

### Vérifier la chaîne d'audit (régulateur-friendly)

À tout moment :

```bash
lmbox-bridge verify \
  --audit /var/lib/lmbox-bridge/audit.log \
  --genesis "<votre genesis dans config.yaml>"
# verify: OK — 1247 entries chained intact
```

Si la chaîne renvoie un break, **personne** n'a pu modifier les
entrées passées sans être détecté. C'est l'argument SOC 2 / CNIL /
ACPR opposable.

---

## Support

| Problème | Action |
|---|---|
| Service ne démarre pas | `journalctl -u lmbox-bridge -n 100 --no-pager` |
| Box affiche "bridge unreachable" | Vérifier que la box voit la VM Bridge sur le LAN (port 8443) |
| `/readyz` renvoie 503 | Vérifier la règle firewall sortante vers `*.lmbox.eu:443` |
| Chaîne d'audit cassée | Contacter immédiatement votre intégrateur — incident sécurité |

Contact partenaire LMbox : votre intégrateur (Sopra / Inetum / etc.)
ou en direct : `partenaires@lmbox.eu`.
