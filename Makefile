CC = gcc
Version = $(shell sed -n '/^VERSION=/s/VERSION=\(.*\)/\1/p' uv.cygport)
#Debug = -g

cyguv-$(Version).dll libuv-$(Version).dll.a uv.pc: cyguv.c uv.pc.in
	$(CC) $(Debug) -shared -o cyguv-$(Version).dll -Wl,--out-implib=libuv-$(Version).dll.a -I../libuv-v1.9.1/include cyguv.c cyguv-pfns.c
	[ -n "$(Debug)" ] || strip cyguv-$(Version).dll
	sed "s/@Version@/$(Version)/g" uv.pc.in > uv.pc

cyguv-test.exe: cyguv-test.c cyguv-$(Version).dll libuv-$(Version).dll.a
	$(CC) $(Debug) -o cyguv-test.exe -I../../inc/uv -Dcyguv cyguv-test.c -L$(PWD) -luv-$(Version)

cygport:
	git clean -dfx
	(\
		cd `git rev-parse --show-toplevel` &&\
		Stash=`git stash create` &&\
		git archive --prefix=cyguv/ --format=tar.gz $${Stash:-HEAD}\
			> opt/cyguv/cyguv.tar.gz\
	)
	CYGPORT_SRC_URI=cyguv.tar.gz CYGPORT_SRC_DIR=cyguv cygport uv.cygport download prep compile install package

clean:
	rm cyguv-$(Version).dll libuv-$(Version).dll.a