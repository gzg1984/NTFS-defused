#include <linux/slab.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/platform_device.h>

#define DRV_NAME "nolan"
#define MY_MAJOR 50

struct mydev {
	unsigned long phy_iomem;
	unsigned long phy_ioport;
	unsigned long irq;
	struct cdev mycdev;
};

struct class *my_class;

static int my_open(struct inode *inode, struct file *filp)
{
	return 0;
}

static int my_release(struct inode *inode, struct file *filp)
{
	return 0;
}

static ssize_t my_read(struct file *filp, char __user *buf, size_t count, loff_t *f_pos)
{
	return count;
}

static ssize_t my_write(struct file *filp, const char __user *buf, size_t count, loff_t *f_pos)
{
	return count;
}

static struct file_operations my_fops = {
	.open = my_open,
	.release = my_release,
	.read = my_read,
	.write = my_write,
	.owner = THIS_MODULE,
};

static int my_probe(struct platform_device *pdev)
{
	struct resource *res;
	struct mydev *dev;
	//struct class_device *class_dev;
	struct device *class_dev;

	dev_t devno;
	int ret;
	
	printk("Probe pdev->name: %s ; pdev->id: %d\n", pdev->name, pdev->id);
	dev = (struct mydev *)kmalloc(sizeof(*dev), GFP_KERNEL);
	if (NULL == dev)
		return -ENOMEM;

	/* get iomem address */
	res = platform_get_resource(pdev, IORESOURCE_MEM, 0);
	dev->phy_iomem = res->start;
	printk("Phy iomem = 0x%lx\n", dev->phy_iomem);

	/* get ioport address */
	res = platform_get_resource(pdev, IORESOURCE_IO, 0);
	dev->phy_ioport = res->start;
	printk("Phy ioport = 0x%lx\n", dev->phy_ioport);

	/* get irq */
	res = platform_get_resource(pdev, IORESOURCE_IRQ, 0);
	dev->irq = res->start;
	printk("Phy irq = 0x%lx\n", dev->irq);

	/* request char region */
	devno = MKDEV(MY_MAJOR, pdev->id);
	ret = register_chrdev_region(devno, 1, "SKEL_CHAR");
	if (ret) {
		kfree(dev);
		return -1;
	}

	/* add cdev */
	cdev_init(&dev->mycdev, &my_fops);
	dev->mycdev.owner = THIS_MODULE;
	cdev_add(&dev->mycdev, devno, 1);

	/* create /sys/class/xxx */


	class_dev = device_create(my_class, /* class */
			NULL, /* parent */
			devno, /* dev_t */
			&pdev->dev, /* device* */
			"shrek-%d", pdev->id); /* name */
			/*
	if (IS_ERR(class_dev)) {
		printk("Cannot create /sys/class/xxx\n");
		cdev_del(&dev->mycdev);
		unregister_chrdev_region(devno, 1);
		kfree(dev);
		return PTR_ERR(class_dev);
	}

*/
	/* save dev to pdev */
	platform_set_drvdata(pdev, dev);

	return 0;
}

static int  my_remove(struct platform_device *pdev)
{
	struct mydev *dev = platform_get_drvdata(pdev);
	dev_t devno = MKDEV(MY_MAJOR, pdev->id);

	printk("Remove pdev->name: %s ; pdev->id: %d\n", pdev->name, pdev->id);

	//class_device_destroy(my_class, devno);
	device_destroy(my_class, devno);

	cdev_del(&dev->mycdev);
	unregister_chrdev_region(devno, 1);
	kfree(dev);

	platform_set_drvdata(pdev, NULL);
	return 0;
}

static struct platform_driver my_drv = {
	.probe = my_probe,
	.remove = my_remove,
	.driver = {
		.name = DRV_NAME,
		.owner = THIS_MODULE,
	},
};

extern int sys_init(void)
{
	my_class = class_create(THIS_MODULE, "uplooking");
	if (IS_ERR(my_class))
		return PTR_ERR(my_class);

	return platform_driver_register(&my_drv);
}

extern void sys_exit(void)
{
	platform_driver_unregister(&my_drv);
	class_destroy(my_class);
}


