# deploy/execution-sandbox.fr.md — confiner ce que le harnais exécute (issue #180)

_English version: [execution-sandbox.md](execution-sandbox.md)._

**TBP n'exécute jamais rien.** Le broker, OPA et le PEP *décident* : ils répondent
allow ou deny. Ils n'ouvrent jamais un fichier, ne lancent jamais un processus, ne
sandboxent jamais rien (§4.5, « l'action exécutée est l'action traduite »). C'est
délibéré et doit le rester.

Confiner l'*exécution effective* d'une action autorisée est donc **entièrement à la charge
de l'intégrateur** — celui qui branche son propre harnais (cadriciel d'agent, exécuteur
d'outils) sur TBP (« Before Tool Execution » dans `tbp4.2.1/reference-stub/reference_stub_README.md` :
TBP répond, l'application appelante exécute). Cette page est une référence pour qui écrit ce
harnais. Documentation seule : aucun changement du code de TBP.

> Un « allow » de TBP dit *cette action est permise par la politique*. Il ne dit pas *cette
> fonction est sûre*. Si l'exécuteur fait confiance au chemin reçu, un `write_file("notes/a.txt")`
> permis et un lien symbolique qui sort de l'espace de travail sont, pour TBP, le même appel.

## Quatre règles

1. **Résoudre avant de vérifier, et ne pas vérifier-puis-utiliser.** `os.path.abspath` ne
   résout pas les liens symboliques. `os.path.realpath` le fait, et `os.path.commonpath([racine, final])`
   contre la racine confinée ferme la traversée par `..` ou par encodage que la comparaison naïve
   de préfixe laisse passer. Mais `realpath` + `commonpath` + `open` laisse une fenêtre entre la
   vérification et l'ouverture (TOCTOU) : si quelque chose peut remplacer un répertoire par un lien
   symbolique entre les deux, la vérification a porté sur un chemin qui n'est plus celui qu'on ouvre.
   Préférer **une seule ouverture sans course, sous la racine** — ci-dessous — et garder
   `realpath`/`commonpath` comme premier filtre portable, pas comme seul filtre.
2. **L'exécuteur est un processus séparé** du point de décision, avec son propre compte sans
   privilège, une vue du système de fichiers limitée à l'espace de travail (espace de noms de
   montage, conteneur, ou au moins un utilisateur et un répertoire dédiés), aucun secret du plan de
   décision et aucune route vers le plan d'administration. C'est la séparation décider/exécuter que TBP
   impose déjà, appliquée côté intégrateur.
3. **Une liste blanche explicite d'actions**, jamais un exécuteur générique « lance cette commande »
   ou « appelle cette fonction par son nom ». Chaque action a des paramètres typés, validés par
   l'exécuteur lui-même (longueur, jeu de caractères, énumérations), pas seulement par la politique.
4. **Exécuter exactement ce qui a été autorisé.** Lier l'exécution à la décision : l'exécuteur lance
   l'action *et les paramètres* que TBP a évalués (comparer un condensé de la requête canonique avec
   celui de la décision), pas une relecture de la sortie de l'agent.

## Ouvrir sous une racine (Python)

`openat2` avec `RESOLVE_BENEATH` est la réponse du noyau (Linux ≥ 5.6) et le meilleur outil quand le
langage l'expose. L'équivalent portable ci-dessous parcourt le chemin composant par composant avec
`dir_fd` et `O_NOFOLLOW` : un lien symbolique sur le chemin est refusé, et il n'y a pas de fenêtre
entre vérifier et utiliser, puisqu'il n'y a pas de vérification séparée.

```python
import os, stat

class SandboxViolation(PermissionError):
    pass

def open_beneath(root_fd: int, user_path: str, flags: int, mode: int = 0o600) -> int:
    """Open user_path relative to root_fd, never leaving it.

    Walks the path one component at a time with dir_fd and O_NOFOLLOW: a symlink
    anywhere on the way is refused, so there is no window between "check" and
    "use" for a swap (unlike realpath + commonpath + open).
    """
    parts = [p for p in user_path.split("/") if p not in ("", ".")]
    if not parts or ".." in parts or "\0" in user_path:
        raise SandboxViolation(f"chemin refusé : {user_path!r}")
    dir_fd = os.dup(root_fd)
    try:
        for name in parts[:-1]:
            nxt = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=dir_fd)
            os.close(dir_fd)
            dir_fd = nxt
        fd = os.open(parts[-1], flags | os.O_NOFOLLOW | os.O_CLOEXEC, mode, dir_fd=dir_fd)
    except OSError as e:
        raise SandboxViolation(f"accès refusé : {user_path!r} ({e.strerror})") from e
    finally:
        os.close(dir_fd)
    if not stat.S_ISREG(os.fstat(fd).st_mode):
        os.close(fd)
        raise SandboxViolation(f"pas un fichier ordinaire : {user_path!r}")
    return fd

def write_file(root_fd: int, path: str, content: bytes) -> dict:
    fd = open_beneath(root_fd, path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC)
    with os.fdopen(fd, "wb") as f:
        f.write(content)
    return {"status": "written", "path": path}
```

Le même appel, écrit naïvement, est ce que `tbp4.2.1/tbp-v4-hard-shield/integrations/README.md`
montrait (`open(path, 'w')` sur le chemin reçu). Ce fichier vit dans le dépôt cœur
(`Responsible-Alliance-Protocol`, sous-module `tbp4.2.1`), où l'exemple est annoté « illustration seule, ne pas copier ».

## Quoi tester

Un confinement qu'on n'a jamais attaqué est un pari. Garder ceci comme tests de votre harnais :

| Entrée | Attendu |
|---|---|
| `../x`, `sub/../../x` | refusé |
| un lien symbolique de l'espace de travail vers l'extérieur | refusé |
| un composant de répertoire remplacé par un lien symbolique entre deux appels | refusé |
| un chemin contenant un octet NUL | refusé |
| un répertoire, une FIFO ou un périphérique comme dernier composant | refusé |
| `sub/a.txt` | écrit dans l'espace de travail uniquement |

## Précédent

Le dépôt `invarian_debian` (`debian_broker/shadow_executor.py`) isole l'exécuteur du broker de décision
(`ShadowExecutor` ≠ `broker.py`), tient une liste blanche explicite de plugins et confine les chemins par
`realpath` + `commonpath`. C'est une bonne forme de départ ; ajouter l'ouverture sans course ci-dessus
pour fermer la fenêtre vérifier-puis-utiliser.

## Ce que cela ne couvre pas

La sortie réseau, les limites CPU/mémoire et ce que fait l'outil *autorisé* une fois lancé (un shell,
un navigateur, un client de base de données) relèvent de l'isolation de l'exécuteur, à concevoir.
L'isolation réseau de la cellule TBP elle-même est un autre sujet (#186).
