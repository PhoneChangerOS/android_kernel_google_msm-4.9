#include <linux/cred.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/utsname.h>

/* Keep in sync with XROM_SPOOF_RELEASE in kernel/sys.c (override_release). */
#define XROM_SPOOF_RELEASE "6.1.124-android16-9-ga1b2c3d4e5f6"

static int version_proc_show(struct seq_file *m, void *v)
{
	const char *release = utsname()->release;

	/*
	 * Anti-detect: report the spoofed GKI release to app-uid callers so
	 * /proc/version stays consistent with what uname() returns to them
	 * (kernel/sys.c override_release). Detectors (com.chunqiunativecheck
	 * "Spoofed kernel") cross-check uname() vs /proc/version; a mismatch
	 * flags a spoofed kernel. System/root callers (uid < AID_APP_START)
	 * keep the real 4.9 release.
	 */
	if ((from_kuid_munged(current_user_ns(), current_uid()) % 100000) >= 10000)
		release = XROM_SPOOF_RELEASE;

	seq_printf(m, linux_proc_banner,
		utsname()->sysname,
		release,
		utsname()->version);
	return 0;
}

static int version_proc_open(struct inode *inode, struct file *file)
{
	return single_open(file, version_proc_show, NULL);
}

static const struct file_operations version_proc_fops = {
	.open		= version_proc_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
};

static int __init proc_version_init(void)
{
	proc_create("version", 0, NULL, &version_proc_fops);
	return 0;
}
fs_initcall(proc_version_init);
