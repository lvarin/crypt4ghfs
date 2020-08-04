


run:
	docker run -d --rm \
               --name crypt4ghfs \
	       --device=/dev/fuse \
	       --cap-add SYS_ADMIN \
	       --security-opt apparmor:unconfined \
	       --dns-opt "ndots:1" \
	       -v $(shell pwd)/../testfiles:/testfiles \
	       -v $(shell pwd):/code \
               --entrypoint "/bin/sleep" \
               crg/outbox:dev \
           1000000000000
down:
	docker kill crypt4ghfs

exec:
	docker exec -it crypt4ghfs bash

purge:
	docker images -f "dangling=true" -q | uniq | while read n; do docker rmi -f $$n; done
