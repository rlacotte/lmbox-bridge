# LMbox Bridge — enrolment runbook (LMbox staff + certified partners)

Procédure pas-à-pas pour générer la PKI d'un client et lui livrer
son kit d'installation. Cette procédure est exécutée par un opérateur
LMbox (ou un partenaire intégrateur certifié), **pas** par le RSSI
client — lui reçoit le `.tar.gz` final et suit
[docs/INSTALL.md](INSTALL.md).

**Temps prévu** : 10 minutes par client.
**Outils requis** : `lmbox-bridge-enroll` (binaire signé), accès à
la machine vault qui héberge la cloud CA LMbox.

---

## 0. Pré-requis : la cloud CA LMbox

L'opérateur dispose des artefacts cloud CA (typiquement dans
`/etc/lmbox/cloud-ca.crt` + `/etc/lmbox/cloud-ca.key` sur la machine
vault). Ces fichiers sont **uniques pour toute LMbox** — pas par
client. Ils signent le cert outbound de chaque Bridge enrôlé pour
que `app.lmbox.eu` puisse authentifier le Bridge.

⚠ La clé privée cloud CA est l'artefact le plus sensible de LMbox.
Stockée dans Vault avec accès humain 2-eyes, jamais sortie en clair
de la machine vault.

## 1. Préparer l'identité client

Demandez au commercial / au partenaire intégrateur :

| Donnée | Format | Exemple |
|---|---|---|
| `customer-id` | kebab-case, immuable | `acme-industries` |
| `customer-name` | nom légal complet | `Acme Industries SAS` |
| Hostname(s) DMZ de la Bridge VM | FQDN ou IP | `bridge.acme.example.com` ou `10.0.50.42` |

Le `customer-id` finit dans le path des certs et dans la genesis de
l'audit chain. **Une fois choisi, on ne change plus** — ça
casserait la chaîne de preuve cryptographique.

## 2. Initialiser le client

```bash
lmbox-bridge-enroll customer-init \
    --customer-id acme-industries \
    --customer-name "Acme Industries SAS" \
    --output /var/lib/lmbox-enrolments \
    --ca-lifetime 5y
```

Résultat : `/var/lib/lmbox-enrolments/acme-industries/` contient :

```
root/root-ca.crt        ← root CA cert
root/root-ca.key        ← root CA private key (CHMOD 0600)
bridge/box-ca.pem       ← copie du root cert, ce que le Bridge trustera
crl/box-revocations.crl ← CRL vide signée par le root
config.yaml             ← template config pré-renseigné
enrolment.json          ← inventaire métadonnées
```

🔒 **Le `root/root-ca.key` ne sort JAMAIS de la machine vault.**
Toute génération future de cert pour ce client se fait depuis cette
machine.

## 3. Émettre le cert serveur du Bridge

Avec les DNS / IP que le RSSI client va utiliser sur la VM DMZ :

```bash
lmbox-bridge-enroll mint-bridge-server \
    --customer-id acme-industries \
    --output /var/lib/lmbox-enrolments \
    --dns bridge.acme.example.com,bridge.acme.local \
    --ip 10.0.50.42 \
    --lifetime 1y
```

Si le RSSI ne sait pas encore exactement quels SANs il veut, on
ré-émet plus tard — c'est gratuit. Mais il faut au moins UN SAN
(DNS ou IP), sinon les boxes ne pourront pas valider le cert.

## 4. Émettre le cert outbound (vers cloud LMbox)

```bash
lmbox-bridge-enroll mint-bridge-outbound \
    --customer-id acme-industries \
    --output /var/lib/lmbox-enrolments \
    --cloud-ca-cert /etc/lmbox/cloud-ca.crt \
    --cloud-ca-key /etc/lmbox/cloud-ca.key \
    --lifetime 1y
```

Le CN du cert est `bridge-<customer-id>`. C'est ce CN que la cloud
LMbox utilise pour identifier qui parle (et appliquer les quotas /
audit chain cloud-side).

## 5. Émettre les certs des boxes

Pour chaque box que le client va recevoir physiquement :

```bash
lmbox-bridge-enroll mint-box-cert \
    --customer-id acme-industries \
    --output /var/lib/lmbox-enrolments \
    --serial BOX-ACME-001 \
    --lifetime 2y
```

Ces certs vont au **factory provisioning** de la box, pas au kit
client. Une box arrive chez le client déjà pré-flashée avec son
cert dans `/etc/lmbox/client.crt|key`. La box ne sait rien de la
clé root CA — elle a juste son cert client + l'adresse du Bridge.

Répéter pour chaque box. À 60 boxes prévues, on peut scripter :

```bash
for n in 001 002 003 …; do
  lmbox-bridge-enroll mint-box-cert \
    --customer-id acme-industries \
    --serial BOX-ACME-$n
done
```

## 6. Empaqueter le kit client

```bash
lmbox-bridge-enroll pack-kit \
    --customer-id acme-industries \
    --source /var/lib/lmbox-enrolments \
    --hmac-key /etc/lmbox/partners/sopra.hmac \
    --output ./out/acme-industries-bridge-kit.tar.gz
```

Le kit contient (et seulement) :

```
certs/bridge-server.crt
certs/bridge-server.key
certs/bridge-out.crt
certs/bridge-out.key
certs/box-ca.pem
certs/box-revocations.crl
config.yaml
```

Le `root/root-ca.key` et les `boxes/*.{crt,key}` ne sont **pas**
dans le kit. Les keys boxes vont au factory ; la clé root reste au
vault LMbox.

Sortie attendue :

```
✓ kit packed at ./out/acme-industries-bridge-kit.tar.gz
  HMAC-SHA256 : a1b2c3...
  signature   : ./out/acme-industries-bridge-kit.tar.gz.hmac
  → ship both files to the customer's RSSI alongside the partner HMAC key (out-of-band).
```

## 7. Livrer au RSSI

3 artefacts à transmettre, idéalement par 2 canaux différents :

| Artefact | Comment | Pourquoi |
|---|---|---|
| `acme-industries-bridge-kit.tar.gz` | email / partage sécurisé | Le kit lui-même |
| `acme-industries-bridge-kit.tar.gz.hmac` | même canal que le kit | Signature HMAC pour vérification d'intégrité |
| Clé HMAC partenaire (`sopra.hmac`) | **canal différent** (SMS, appel, courrier signé) | Sans la clé HMAC, on ne peut pas vérifier le kit |

Le RSSI lance ensuite `lmbox-bridge-enroll verify-kit` pour confirmer
l'intégrité avant le déploiement (voir [INSTALL.md](INSTALL.md)).

## 8. Inventorier

`enrolment.json` du client contient maintenant la liste exhaustive
des certs émis :

```json
{
  "customer_id": "acme-industries",
  "customer_name": "Acme Industries SAS",
  "created_at": "2026-05-13T22:00:00Z",
  "tool_version": "0.1.0",
  "root_ca": {
    "serial": "1f2a3b…",
    "cn": "lmbox-customer-root",
    "not_before": "2026-05-13T22:00:00Z",
    "not_after": "2031-05-13T22:00:00Z"
  },
  "bridge_server": { … },
  "bridge_outbound": { … },
  "boxes": [
    { "serial": "…", "cn": "BOX-ACME-001", … }
  ],
  "audit_genesis": "acme-industries|2026-05-13T22:00:00Z"
}
```

Cette inventaire est **votre référentiel de rotation**. Au bout d'un
an, vous interrogez `enrolment.json` pour savoir quels certs
arrivent à expiration et émettez les renouvellements.

---

## Procédures opérationnelles courantes

### Révoquer un cert de box (box volée, compromise, restituée)

```bash
# 1. Ajouter le serial à la CRL (futur sous-commande lmbox-bridge-enroll revoke)
# 2. Re-signer la CRL avec le root CA
# 3. Pousser la nouvelle CRL aux Bridges concernés
```

(Sous-commande `revoke` dans v0.2 — pour l'instant, opération manuelle
avec `openssl ca -revoke`.)

### Renouveler le cert serveur du Bridge avant expiration

Mêmes paramètres que `mint-bridge-server` la première fois — le
fichier est écrasé. Pousser la nouvelle paire au RSSI dans un kit
"refresh" minimal :

```bash
lmbox-bridge-enroll mint-bridge-server \
    --customer-id acme-industries \
    --dns bridge.acme.example.com \
    --ip 10.0.50.42 \
    --lifetime 1y

# Re-pack un kit refresh (mêmes flags, nouveau output).
lmbox-bridge-enroll pack-kit \
    --customer-id acme-industries \
    --hmac-key /etc/lmbox/partners/sopra.hmac \
    --output ./out/acme-industries-bridge-refresh-$(date +%Y%m).tar.gz
```

Le RSSI déploie en suivant le même runbook qu'initialement, suivi
d'un `systemctl restart lmbox-bridge`.

### Émettre un cert d'urgence (box en panne, remplacée immédiatement)

Le partenaire intégrateur sur place a-t-il accès à `lmbox-bridge-enroll`
+ une copie de la cloud CA cert/key ? Si oui (cas "Certified
Installer Tier 2") :

```bash
# Sur le laptop partenaire, après vérification 2FA.
lmbox-bridge-enroll mint-box-cert \
    --customer-id acme-industries \
    --serial BOX-ACME-042 \
    --lifetime 30d   # cert court terme, remplacé au prochain shipping factory
```

Sinon → ticket urgence à LMbox staff, SLA < 2 h.

---

## Sécurité de la machine d'enrôlement

La machine qui exécute `lmbox-bridge-enroll` détient :

1. Les clés privées des **N root CAs** clients (1 par client enrôlé)
2. La clé privée de la **cloud CA LMbox**
3. Les clés HMAC de chaque **partenaire**

Pour ces raisons :

- 🔒 Disque chiffré at-rest (LUKS / FileVault / equivalent)
- 🔒 Pas d'accès SSH externe — bastion + jumphost mandatory
- 🔒 Audit log toutes les invocations de `lmbox-bridge-enroll`
- 🔒 2 humains required pour produire un kit (séparation des
  fonctions : un fait la commande, l'autre revoit la sortie avant
  envoi RSSI)
- 🔒 Backup chiffré quotidien vers une 2e localisation géographique
- 🔒 Rotation des clés HMAC partenaires tous les 12 mois minimum
