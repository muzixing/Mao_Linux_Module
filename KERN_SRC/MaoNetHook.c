/*
===============================================================================
Driver Name		:		MaoNetHook
Author			:		JIANWEI MAO
License			:		GPL
Description		:		LINUX DEVICE DRIVER PROJECT
===============================================================================
*/

#include "MaoNetHook.h"
#include <linux/slab.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Jianwei Mao");



struct kobject * mao_sysfs_root;
char * statusBuff;



ssize_t	mao_sysfs_read(struct kobject * kobj, struct attribute * attr, char * buff)
{
//	int i;
//	for (i = 0; i<PAGE_SIZE; i++)
//	{
//		buff[i] = '5'+(i%10);
//	}
	memcpy(buff, statusBuff, PAGE_SIZE);

	PINFO("READ, Dir: %s, File: %s, Buf:%s, Size:%ld, StrLen:%ld, %ld", kobj->name, attr->name, buff, sizeof(buff), strlen(buff), PAGE_SIZE);

	return PAGE_SIZE - 1;
}

ssize_t	mao_sysfs_write(struct kobject * kobj, struct attribute * attr, const char * buff, size_t count)
{
	PINFO("WRITE, Dir: %s, File: %s, Buf:%s, Size:%ld, StrLen:%ld, ActualCount:%ld, %ld", kobj->name, attr->name, buff, sizeof(buff), strlen(buff), count, PAGE_SIZE);

	memcpy(statusBuff, buff, count);

	PINFO("WRITE2, %ld, %ld, %ld, %d, %d, %d",
			ksize(buff), count, strlen(buff), buff[count-1], buff[count], buff[count+1]);

	return count;
}

struct attribute mao_sysfs_default_attr = {
		.name = "status",
		.mode = 0666
};

struct sysfs_ops mao_sysfs_func = {
		.show = mao_sysfs_read,
		.store = mao_sysfs_write
};

struct kobj_type mao_sysfs_type = {
		.sysfs_ops = &mao_sysfs_func
};

static int __init MaoNetHook_init(void)
{
	/* TODO Auto-generated Function Stub */

	PINFO("INIT\n");

	statusBuff = kzalloc(PAGE_SIZE, GFP_KERNEL);

	mao_sysfs_root = kobject_create_and_add("mao", NULL);
	mao_sysfs_root->ktype = &mao_sysfs_type;

	PINFO("%d", sysfs_create_file(mao_sysfs_root, &mao_sysfs_default_attr));

	return 0;
}

static void __exit MaoNetHook_exit(void)
{
	/* TODO Auto-generated Function Stub */

	sysfs_remove_file(mao_sysfs_root, &mao_sysfs_default_attr);

	kzfree(statusBuff);

	kobject_del(mao_sysfs_root);

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

