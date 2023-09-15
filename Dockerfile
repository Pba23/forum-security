# Utilisez une image de base avec Go préinstallé
FROM golang:1.19

LABEL MAINTAINER: "lomalack pba papgueye serignmbaye"

# Définissez le répertoire de travail dans le conteneur
WORKDIR /app

# Copiez les fichiers de votre application Go dans le conteneur
COPY . .

RUN go mod download golang.org/x/net

# Construisez l'application Go
RUN go build -o main .

# Exposez un port pour que l'application puisse être accessible depuis l'extérieur
EXPOSE 8080

# Commande pour démarrer l'application lorsque le conteneur est en cours d'exécution
CMD [ "./main" ]
