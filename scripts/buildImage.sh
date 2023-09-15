cd ..

sudo docker image build -f Dockerfile -t forum .

sudo docker images

sudo docker container run -p 8080 --detach --name container-test forum

sudo docker pa -a

sudo docker run -p 8080:8080 forum