MONITOR=cadvisor

build:
	docker build -f Dockerfile.server -t honey:latest --network=host .

run: run_monitor run_honeypot

run_monitor:
	docker run \
	--volume=/:/rootfs:ro \
	--volume=/var/run:/var/run:ro \
	--volume=/sys:/sys:ro \
	--volume=/var/lib/docker/:/var/lib/docker:ro \
	--volume=/dev/disk/:/dev/disk:ro \
	--network=host \
	--detach=true \
	--name=${MONITOR} \
  	gcr.io/google-containers/cadvisor:latest

run_honeypot:
	python3 main.py config.json


clean: clean_honeypot clean_monitor

clean_honeypot: clean_mininet clean_logs

clean_mininet:
	mn -c
clean_monitor:
	docker container stop ${MONITOR}
	docker container rm ${MONITOR}
clean_logs:
	rm honeyLogs.txt