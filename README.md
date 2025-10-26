# Bash Scripting - Automatisation de la Configuration des Serveurs

## Description du Projet

Ce projet a pour objectif l'**automatisation de la configuration de serveurs réseau** à l'aide de scripts Bash. Il permet de déployer rapidement et de manière répétable des services essentiels tels que **DHCP, DNS, FTP, SMTP et POP/IMAP** sur des systèmes Linux. L'automatisation réduit les erreurs humaines, accélère le déploiement et facilite la maintenance des serveurs.

Le projet couvre les aspects suivants :

- **Installation automatique des services** : le script installe les paquets nécessaires selon le service configuré.  
- **Configuration initiale** : génération et mise à jour des fichiers de configuration pour chaque serveur.  
- **Gestion des utilisateurs et permissions** : création de comptes FTP et SMTP si nécessaire.  
- **Journalisation et suivi** : logs pour chaque étape de configuration afin de vérifier le succès des opérations.  
- **Flexibilité et personnalisation** : les paramètres comme les adresses IP, les noms de domaine, et les répertoires peuvent être facilement modifiés.  

---

## Services Automatisés

| Service | Description |
|---------|------------|
| **DHCP** | Configuration d’un serveur DHCP pour attribuer automatiquement des adresses IP aux clients. |
| **DNS**  | Configuration d’un serveur DNS pour la résolution des noms de domaine locaux. |
| **FTP**  | Mise en place d’un serveur FTP pour le transfert de fichiers entre clients et serveurs. |
| **SMTP** | Mise en place d’un serveur SMTP pour l’envoi d’emails. |
| **POP/IMAP** | Configuration pour la réception des emails via POP3 ou IMAP. |

---
