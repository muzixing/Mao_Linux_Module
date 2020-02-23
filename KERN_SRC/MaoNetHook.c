/*
===============================================================================
Driver Name		:		MaoNetHook
Author			:		JIANWEI MAO
License			:		GPL
Description		:		LINUX DEVICE DRIVER PROJECT
===============================================================================
*/

#include"MaoNetHook.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Jianwei Mao");

static int __init MaoNetHook_init(void)
{
	/* TODO Auto-generated Function Stub */

	PINFO("INIT\n");

	return 0;
}

static void __exit MaoNetHook_exit(void)
{	
	/* TODO Auto-generated Function Stub */

	PINFO("EXIT\n");

}


//MODULE_LICENSE("Mao Private.");
//MODULE_AUTHOR("Jianwei Mao");
MODULE_DESCRIPTION("Mao linux module architecture.");
MODULE_VERSION("Mao v0.1");

MODULE_FIRMWARE("I need firmware1: qingdao");
MODULE_FIRMWARE("I need firmware2: beijing");

MODULE_ALIAS("Mao Alias.");
MODULE_SOFTDEP("Mao deps");

module_init(MaoNetHook_init);
module_exit(MaoNetHook_exit);

