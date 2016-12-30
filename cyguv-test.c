
#include <stdio.h>
#include "libuv/include/uv.h"

const char* cyguv_version_string(void);

int main()
{
	const char * version = NULL;
	uv_loop_t* loop = NULL;
	
	cyguv_init(1);
	
	version = uv_version_string();
	loop = uv_default_loop();
	printf("libuv version is %s\n", version);
	printf("init a loop at %p\n", loop);
}
