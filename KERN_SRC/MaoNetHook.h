
#define DRIVER_NAME "MaoNetHook"
#define PDEBUG(fmt,args...) printk(KERN_DEBUG"%s:"fmt"\n",DRIVER_NAME, ##args)
#define PERR(fmt,args...) printk(KERN_ERR"%s:"fmt"\n",DRIVER_NAME,##args)
#define PINFO(fmt,args...) printk(KERN_INFO"%s:"fmt"\n",DRIVER_NAME, ##args)
#include<linux/init.h>
#include<linux/module.h>
