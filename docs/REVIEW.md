# Revue de HTTPdis — septembre 2026

## Pertinence

HTTPdis rend un service précis aux applications existantes : exposer leurs commandes
et métriques HTTP avec les mêmes conventions de routage et de réponse. Sa valeur est
celle d'un composant intégré. Pour un nouveau projet sans dépendance à cet écosystème,
son entretien doit être comparé à celui d'un framework maintenu ; il n'a pas besoin de
devenir un framework web généraliste pour rester utile.

## Code et algorithmes

L'enregistrement des routes et les hooks sont compréhensibles. Le gros module central,
les variables globales et le protocole HTTP géré en partie à la main augmentent cependant
le coût de maintenance. Les défauts reproduits portent sur Basic Auth, l'état partagé
entre threads, les longueurs UTF-8, les fichiers statiques et la conversion JSON des
anciens interpréteurs. La version 0.6.27 corrige ces points et ajoute des échanges HTTP
réels aux tests. Les traces d'exception ne sont plus exposées automatiquement aux clients.

Les routes exactes ont un accès par dictionnaire. Les routes regex restent parcourues
séquentiellement ; c'est acceptable pour un petit service mais ce n'est pas un routeur
optimisé pour des milliers de routes. Les fichiers statiques sont encore chargés en
mémoire et l'exécution est synchrone : documenter ces choix est plus utile que promettre
une montée en charge non mesurée.

## Architecture et limites

Conserver l'API existante pour les services utilisateurs. Séparer ultérieurement le
routage, l'authentification et les transports, puis évaluer un adaptateur WSGI/ASGI si
les besoins le justifient. Garder HTTPdis derrière un reverse proxy pour TLS, les délais
et les limites de connexion. Les contrôles de chemins ne constituent pas un sandbox
contre un utilisateur qui peut modifier simultanément le répertoire statique.

La campagne n'est ni un audit protocolaire exhaustif ni un benchmark de charge. Les
anciens formats de mot de passe restent lisibles par compatibilité ; ils ne constituent
pas une recommandation de stockage pour de nouvelles applications. Le clin d'œil au
TARDIS fait partie de l'identité du projet, pas de sa description technique.
