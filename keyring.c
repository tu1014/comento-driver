#include <linux/module.h>
#include <linux/device.h>
#include <linux/fs.h>
#include <linux/spinlock.h>
#include <linux/types.h>
#include <linux/list.h>

#define KEYRING_DEVICE_NAME "keyring"
#define KEYRING_CTL_DEVICE_NAME "keyringctl"
#define CLASS_NAME "my-keyring"
#define BUF_SIZE (32 * 8)
#define MAGIC_NUMBER 'C'
#define KEYRING_IOCTL_ADD _IOW(MAGIC_NUMBER, 0, int32_t)
#define KEYRING_IOCTL_DEL _IOW(MAGIC_NUMBER, 1, int32_t)

static int KEYRING_MAJOR_NUMBER = 0;
static int KEYRINGCTL_MINOR_NUMBER = 0;
static struct class* KEYRING_CLASS;
static struct device* KEYRING_DEVICE;

struct keyring_node {
	int minor;
	char buffer[BUF_SIZE];
	struct device* keyring_device;
	struct list_head list;
};

LIST_HEAD(KEYRING_LIST);

static int __init keyring_module_init(void);
static void __exit keyring_module_exit(void);
static int keyring_open(struct inode* inode, struct file* fp);
static ssize_t keyring_read(struct file* fp, char* __user buf, size_t len, loff_t* ppos);
static ssize_t keyring_write(struct file* fp, const char* __user buf, size_t len, loff_t* ppos);
static long keyring_ioctl(struct file* fp, unsigned int cmd, unsigned long arg);
static int add_keyring(int minor);
static int delete_keyring(int minor);
static int is_ctl_device(struct file* fp);

static struct file_operations keyring_fops = {
	.open = keyring_open,
	.read = keyring_read,
	.write = keyring_write,
	.unlocked_ioctl = keyring_ioctl,
};

static int __init keyring_module_init(void)
{
	int ret = 0;
	printk(KERN_DEBUG "MY_KEYRING_INIT : %s\n", __func__);

	KEYRING_MAJOR_NUMBER = register_chrdev(0, KEYRING_DEVICE_NAME, &keyring_fops);
	if(KEYRING_MAJOR_NUMBER < 0) {
		printk(KERN_ERR "%s : Failed to get major number", KEYRING_DEVICE_NAME);
		ret = KEYRING_MAJOR_NUMBER;
		goto err_register_chrdev;
	}

	KEYRING_CLASS = class_create(THIS_MODULE, CLASS_NAME);
	if(IS_ERR(KEYRING_CLASS)) {
		printk(KERN_ERR "%s : Failed to create class", KEYRING_DEVICE_NAME);
		ret = PTR_ERR(KEYRING_CLASS);
		goto err_class;
	}

	KEYRING_DEVICE = device_create(
		KEYRING_CLASS, NULL,
		MKDEV(KEYRING_MAJOR_NUMBER, KEYRINGCTL_MINOR_NUMBER),
		NULL, "%s", KEYRING_CTL_DEVICE_NAME
	);
	/*if(IS_ERR(COMENTO_DEVICE[minor])) {
		ret = PTR_ERR(COMENTO_DEVICE[minor]);
		goto err_device;
	}*/

	return ret;

	err_device:
		class_destroy(KEYRING_CLASS);
	err_class:
		unregister_chrdev(KEYRING_MAJOR_NUMBER, KEYRING_DEVICE_NAME);
	err_register_chrdev:
		return ret;
}

static void __exit keyring_module_exit(void)
{
	printk(KERN_DEBUG "MY_KEYRING_EXIT : %s\n", __func__);

	struct keyring_node* node;
	struct keyring_node* tmp;

	list_for_each_entry_safe(node, tmp, &KEYRING_LIST, list) {

		printk(KERN_INFO "Delete keyring device node : %d\n", node->minor);
		device_destroy(KEYRING_CLASS, MKDEV(KEYRING_MAJOR_NUMBER, node->minor));
		list_del(&node->list);
		kfree(node);

	}

	device_destroy(KEYRING_CLASS, MKDEV(KEYRING_MAJOR_NUMBER, KEYRINGCTL_MINOR_NUMBER));
	class_destroy(KEYRING_CLASS);
	unregister_chrdev(KEYRING_MAJOR_NUMBER, KEYRING_DEVICE_NAME);
}

static int keyring_open(struct inode* inode, struct file* fp)
{
	int minor = iminor(inode);
	printk(KERN_INFO "MY_KEYRING_OPEN - minor : %d\n", minor);

	return 0;
}

static int is_ctl_device(struct file* fp) {
	if(iminor(fp->f_inode) == KEYRINGCTL_MINOR_NUMBER) return 1;
	else return 0;
}

static ssize_t keyring_read(struct file* fp, char* __user buf, size_t len, loff_t* ppos)
{ 
	if(is_ctl_device(fp))
		return -EINVAL;

	struct keyring_node* node;
	struct keyring_node* tmp;

	int minor = iminor(fp->f_inode);

	list_for_each_entry_safe(node, tmp, &KEYRING_LIST, list) {

		if(node->minor == minor) {
			int read_bytes = 0;
			read_bytes =  len - copy_to_user(buf, node->buffer, len);
			return read_bytes;
		}

	}
	
	return -EINVAL;
}

static ssize_t keyring_write(struct file* fp, const char* __user buf, size_t len, loff_t* ppos)
{ 
	if(is_ctl_device(fp))
		return -EINVAL;

	struct keyring_node* node;
	struct keyring_node* tmp;

	int minor = iminor(fp->f_inode);

	list_for_each_entry_safe(node, tmp, &KEYRING_LIST, list) {

		if(node->minor == minor) {
			int write_bytes = 0;
			write_bytes =  len - copy_from_user(node->buffer, buf, len);
			return write_bytes;
		}

	}
	
	return -EINVAL;
}

static long keyring_ioctl(struct file* fp, unsigned int cmd, unsigned long arg)
{
	int res = 0;

	if(_IOC_TYPE(cmd) != MAGIC_NUMBER) {
		printk("ioctl : command type mismatch.\n");
		return -1;
	}

	if(is_ctl_device(fp) < 0)
		return -1;

	switch(cmd) {
		case KEYRING_IOCTL_ADD:
			res = add_keyring(arg);
			if(res == -1) {
				printk("ioctl : Failed to add.\n");
				return res;
			}
			break;

		case KEYRING_IOCTL_DEL:
			res = delete_keyring(arg);
			if(res == -1) {
				printk("ioctl : Failed to delete.\n");
				return res;
			}
			break;
		
		default:
			return -EINVAL;
	}

	return 0;
}

static int add_keyring(int minor)
{
	struct keyring_node* node;
	struct keyring_node* tmp;

	list_for_each_entry_safe(node, tmp, &KEYRING_LIST, list) {

		if(node->minor == minor) {
			printk(KERN_INFO "Keyring already exists : %d\n", minor);
			return -1;
		}

	}

	struct keyring_node* new_node;

	struct device* keyring_device = device_create(
		KEYRING_CLASS, NULL,
		MKDEV(KEYRING_MAJOR_NUMBER, minor),
		NULL, "%s%d", KEYRING_DEVICE_NAME, minor
	);
	// TODO: check error
	
	new_node = kmalloc(sizeof(struct keyring_node), GFP_KERNEL);
	if(new_node == NULL) {
		device_destroy(KEYRING_CLASS, MKDEV(KEYRING_MAJOR_NUMBER, minor));
		return -1;
	}

	new_node->minor = minor;
	new_node->keyring_device = keyring_device;

	list_add(&new_node->list, &KEYRING_LIST);
	printk(KERN_INFO "ioctl - add_keyring\n");

	return 0;
}

static int delete_keyring(int minor) {

	struct keyring_node* node;
	struct keyring_node* tmp;

	list_for_each_entry_safe(node, tmp, &KEYRING_LIST, list) {

		if(node->minor == minor) {
			printk(KERN_INFO "Delete keyring device node : %d\n", minor);
			device_destroy(KEYRING_CLASS, MKDEV(KEYRING_MAJOR_NUMBER, minor));
			list_del(&node->list);
			kfree(node);
			return 0;
		}

	}

	return -1;
}

module_init(keyring_module_init);
module_exit(keyring_module_exit);

MODULE_AUTHOR("TAEWOOK AHN <tu1014@naver.com>");
MODULE_DESCRIPTION("Keyring Driver");
MODULE_LICENSE("GPL v2");
