# this script should be run in the root directory of the project with root privileges
# it build the docker images, starts the docker containers and sets the bridge to not age out the MAC addresses
docker build -t ids ./ids
docker build -t client_attacker ./client
docker build -t vulnerable_server ./server
docker-compose up -d
BRIDGE=$(docker network inspect -f '{{.Id}}'    buffer_overflow_1_internal_network | cut -c 1-12 | sed 's/^/br-/')
brctl setageing $BRIDGE 0
brctl setfd $BRIDGE 0