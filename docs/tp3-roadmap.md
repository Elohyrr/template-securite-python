# Roadmap TP3 – Breach the target

> But : écrire un outil `tp3` qui, lancé avec `--target http://host:8080`, trouve **FLAG1** (phase web)
> puis **FLAG_FINAL** (phase réseau) et les affiche. Objectif perso : le faire en 3-4 jours.

---

## 0. Comprendre le jeu avant de coder

Trois cibles différentes, à ne pas confondre :

1. **Copie locale (Docker)** : drapeaux bidons, pas de limite de temps. C'est ton labo, tu bosses dessus 99% du temps.
2. **Instance hébergée** : tes vrais drapeaux, mais **5 min de vie** et **3 démarrages/heure**. Tu l'utilises
   seulement quand ton exploit marche déjà en local, juste pour vérifier.
3. **Cible de correction** : la plateforme relance ton code sur une cible neuve avec des drapeaux tirés au hasard.
   → Conséquence : **interdit de coder un drapeau en dur**. Ton outil doit *vraiment* les récupérer à chaque fois.

Le flux complet :

```
--target http://host:8080
   │
   ├─ PHASE WEB ─────────────────────────────┐
   │   1. fuzzing : trouver la page cachée    │
   │   2. récupérer l'image du CAPTCHA        │
   │   3. résoudre le CAPTCHA (OCR)           │
   │   4. renvoyer la réponse                 │
   │   → la page donne : FLAG1 + host:port + clé │
   │                                          │
   └─ PHASE RÉSEAU ──────────────────────────┤
       5. se connecter en TCP à host:port     │
       6. boucle : recevoir jeton → base64 →  │
          XOR avec la clé → renvoyer la réponse│
          (sous ~5 s par round)               │
       → après N rounds : FLAG_FINAL ─────────┘
```

---

## Jour 1 — Monter le labo + explorer à la main

Le but du jour 1 : **ne pas écrire une ligne d'exploit**. Juste faire tourner la cible et tout faire *à la main*
(navigateur, curl, netcat) pour comprendre ce que le serveur attend. Tu ne peux pas automatiser ce que tu n'as
pas compris manuellement.

### 1.1 Lancer la cible locale
```bash
docker load -i tp3-target.tar.gz
docker compose up
```
Vérifie : `http://localhost:8080` répond dans le navigateur.

### 1.2 Explorer le web à la main
- Ouvre la page d'accueil, regarde le code source (clic droit → afficher source).
- Teste quelques URLs au pif : `/admin`, `/login`, `/secret`, `/robots.txt`.
- Objectif : comprendre à quoi ressemble une page qui existe (code 200) vs une qui n'existe pas (404).
  C'est LA base du fuzzing : on bombarde d'URLs et on garde celles qui ne répondent pas 404.

### 1.3 Préparer l'environnement Python
Dans `pyproject.toml`, ajoute les dépendances (via `poetry add`) :
- `requests` → faire des requêtes HTTP
- `pillow` (PIL) → manipuler l'image du CAPTCHA
- `pytesseract` → OCR (lire du texte dans une image)
- `pwntools` → faire du réseau TCP facilement (ou `socket`, inclus dans Python)

Et installe le binaire système **tesseract** (l'OCR) : `pytesseract` est juste un wrapper, il a besoin du
programme `tesseract` installé sur la machine. Note-le, c'est un piège classique de débutant.

### 1.4 Préparer la wordlist
Crée `src/tp3/wordlist.txt` : une liste de noms de pages probables, un par ligne
(`admin`, `secret`, `hidden`, `challenge`, `captcha`, `flag`, etc.).
Pendant la correction, **pas d'accès Internet** → la wordlist doit être **dans le projet**
et ouverte par un chemin relatif au code : `Path(__file__).parent / "wordlist.txt"` (pas au dossier courant).

**Fin de journée 1 :** cible qui tourne, env Python prêt, tu sais à la main à quoi ressemble une bonne réponse HTTP.

---

## Jour 2 — Phase web : fuzzing + CAPTCHA → FLAG1

C'est la partie la plus longue. On remplit les classes `Captcha` et `Session` du squelette.

### 2.1 Le fuzzing (trouver la page cachée)
Fonction à écrire, p. ex. `find_hidden_endpoint(target) -> str` :
- Ouvre la wordlist, pour chaque mot construit l'URL `target + "/" + mot`.
- Fais un `requests.get(url)`.
- Garde celle dont le **code de retour n'est pas 404** (souvent 200). C'est ta page cachée.
- Retourne l'URL trouvée.

*Idée clé :* une boucle `for` sur la wordlist + un `if réponse.status_code == 200`. Rien de plus.
Pense à logger chaque URL testée (via `logger` déjà fourni dans `config.py`) pour voir ce qui se passe.

### 2.2 La classe `Captcha` (fichier `captcha.py`)
Le squelette te donne déjà les 4 méthodes. Voici ce que chacune doit faire :

- `__init__(self, url)` : stocke l'URL d'où télécharger l'image. Déjà fait.
- `capture(self)` : **télécharger l'image** du CAPTCHA.
  - `requests.get(url_image)`, récupérer les octets (`.content`).
  - Les charger dans PIL : `Image.open(BytesIO(reponse.content))`.
  - Stocker dans `self.image`.
- `solve(self)` : **lire le texte dans l'image** (le cœur du TP).
  - D'abord un **prétraitement** pour aider l'OCR (le sujet insiste dessus) :
    - passer en noir et blanc (`.convert("L")`),
    - augmenter le contraste / binariser (seuil : pixel > X → blanc, sinon noir),
    - parfois agrandir l'image (×2) ou enlever le bruit.
  - Puis `pytesseract.image_to_string(image_traitee)`.
  - Nettoyer le résultat (enlever espaces, retours ligne, caractères parasites).
  - Stocker dans `self.value`.
  - 👉 C'est **itératif** : tu vas tester, voir que l'OCR lit mal, ajuster le prétraitement, retester.
    Sauvegarde l'image traitée sur disque (`image.save("debug.png")`) pour voir ce que voit tesseract.
- `get_value(self)` : retourne `self.value`. Déjà fait.

### 2.3 La classe `Session` (fichier `session.py`)
Elle orchestre un essai complet « je résous le captcha et je soumets » :

- `prepare_request(self)` : crée un `Captcha`, appelle `.capture()` puis `.solve()`, récupère la valeur.
  (Le squelette le fait déjà en partie — enlève le `"FIXME"`.)
- `submit_request(self)` : **renvoyer la réponse au serveur**.
  - En général un `requests.post(url, data={...})` avec la valeur du captcha dans le bon champ de formulaire.
  - Pense à garder les **cookies/la session** : utilise un même `requests.Session()` pour récupérer l'image
    ET poster la réponse, sinon le serveur ne reconnaît pas ton captcha.
  - Stocke la réponse HTTP.
- `process_response(self)` : **extraire de la réponse** le FLAG1, le `host:port` et la clé.
  - Chercher dans le texte HTML (regex, ou simple découpage de chaîne). Range-les dans des attributs.
- `get_flag(self)` : retourne le flag trouvé.

### 2.4 Brancher dans `main.py` → `breach_web(target)`
`breach_web` doit :
1. appeler le fuzzing → URL cachée,
2. créer une `Session`, boucler `prepare_request` + `submit_request` **jusqu'à ce que le captcha passe**
   (l'OCR rate parfois : refais un essai si refusé),
3. `process_response` → afficher FLAG1 et **retourner `(host, port, key)`** pour la phase réseau.

**Fin de journée 2 :** `poetry run tp3 --target http://localhost:8080` affiche FLAG1 en local.

---

## Jour 3 — Phase réseau : décodage chronométré → FLAG_FINAL

### 3.1 Comprendre l'encodage à la main d'abord
Connecte-toi au service TCP au clavier pour voir les messages :
```bash
nc localhost 9090      # ou le host:port révélé
```
Tu verras arriver des jetons bizarres. L'ordre de décodage donné par le sujet :
**base64 d'abord, puis XOR avec la clé.**

- **base64** : un encodage qui transforme des octets en texte lisible. On le défait avec
  `base64.b64decode(jeton)` → tu récupères des octets bruts.
- **XOR** : chaque octet est combiné avec un octet de la clé via l'opérateur `^`.
  Propriété magique : XOR est réversible. `(data ^ key) ^ key == data`. Donc pour décoder,
  tu re-XOR les octets avec la clé. Si la clé est plus courte que les données, on la répète en boucle.

Mini-illustration du principe (pas la solution, juste le concept) :
```python
# octets = résultat du b64decode
decoded = bytes(o ^ key[i % len(key)] for i, o in enumerate(octets))
```

### 3.2 La fonction `breach_network(host, port, key)`
- **Se connecter** : avec pwntools `io = remote(host, port)` (ou `socket.create_connection`).
- **Boucler** sur les rounds. À chaque round :
  1. recevoir le jeton envoyé par le serveur (`io.recvline()`),
  2. le décoder : `base64.b64decode` → puis XOR avec `key`,
  3. renvoyer le résultat décodé (`io.sendline(resultat)`),
  4. lire ce que répond le serveur (round suivant ? ou le flag ?).
- Le chrono (~5 s/round) : tout doit être automatique et rapide. Pas de `input()`, pas de `print` lourd,
  pas de pause. Une boucle serrée. C'est pour ça qu'on scripte : un humain ne décoderait pas en 5 s.
- **Condition de sortie** : quand la réponse du serveur contient `ESGI{...}` → c'est le FLAG_FINAL, tu le retournes.
  Sinon tu continues la boucle.

### 3.3 Détails qui piquent (prévois-les)
- **bytes vs str** : le réseau, le base64 et le XOR travaillent sur des `bytes`, pas des `str`.
  Convertis au bon moment (`.encode()` / `.decode()`), c'est la source n°1 de bugs ici.
- **la clé** : récupérée à l'étape web, vérifie son format (texte ? hexa ? base64 ?) avant de XOR.
- **fin de ligne** : `recvline`/`sendline` gèrent le `\n`, mais vérifie que le serveur n'attend pas un format précis.

**Fin de journée 3 :** l'outil affiche FLAG1 **et** FLAG_FINAL en local, d'un seul coup.

---

## Jour 4 — Tests, robustesse, validation hébergée, dépôt

### 4.1 Rendre l'outil robuste (sinon la correction aléatoire te plante)
- Le captcha peut rater → **relancer** jusqu'à succès (boucle avec un nombre max d'essais).
- La page cachée peut avoir un autre nom → ta wordlist doit être assez fournie.
- N'écris **rien en dur** (ni URL de page, ni flag, ni clé) : tout est lu dynamiquement.

### 4.2 Les tests (ils comptent dans le barème)
Complète `tests/tp3/...`. Vise des tests qui ne dépendent pas du réseau :
- test du décodage XOR sur un exemple connu (clé + message → résultat attendu),
- test du prétraitement / parsing de la réponse HTML avec une fausse réponse,
- garde les tests du squelette verts.
Lance `poetry run pytest` et le `pre-commit` (il y a un `.pre-commit-config.yaml` dans le repo).

### 4.3 Valider sur l'instance hébergée (ressource rare)
- Seulement quand ça marche en local à 100 %. Tu n'as que **3 démarrages/heure, 5 min chacun**.
- Prépare ta commande à l'avance, démarre l'instance, lance `tp3 --target <adresse_fournie>`, note les 2 flags.
- Si ça rate : debug en local, pas sur l'instance (tu grillerais tes essais).

### 4.4 Déposer
- Vérifie le chemin relatif de la wordlist (`Path(__file__).parent / "wordlist.txt"`).
- Vérifie que `python -m tp3.main --target http://<cible>:8080` marche depuis un **dossier vide**.
- Archive `.zip` avec la structure du template (`src/tp3/main.py`, etc.).
- Dépôts illimités → c'est le **dernier** qui compte, tu peux re-déposer en améliorant.

---

## Récap des fonctions à écrire

| Fichier | Fonction | Rôle en une phrase |
|---|---|---|
| `main.py` | `breach_web` | fuzze, casse le captcha, affiche FLAG1, retourne (host, port, key) |
| `main.py` | `breach_network` | boucle de décodage base64+XOR, retourne FLAG_FINAL |
| `captcha.py` | `capture` | télécharge l'image du captcha |
| `captcha.py` | `solve` | prétraite l'image + OCR → texte |
| `session.py` | `prepare_request` | capture + résout le captcha |
| `session.py` | `submit_request` | poste la réponse (même session HTTP) |
| `session.py` | `process_response` | extrait FLAG1, host:port, clé de la réponse |
