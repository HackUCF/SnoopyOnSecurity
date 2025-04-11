# build for amd64 architecture
docker build --platform linux/amd64 -t go-red .
docker create --name go-red go-red
docker cp go-red:/build/red .
docker rm -f go-red
