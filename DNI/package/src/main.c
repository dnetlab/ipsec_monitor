
/*
 * 由于strongswan的一些局限性，需要额外的监控让ipsec更加健壮，更加稳定，
 * 这里添加一些方法，针对dni系统的ipsec监控程序
 */

#include <stdio.h>  
#include <string.h>  
#include <stdlib.h> 
#include <sys/select.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/inotify.h>  
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/wait.h>

#define WAN_UP 1 
#define WAN_DOWN 0
#define WAN_ERR -1

#define LINK_STATUS_FILE "/tmp/port_status"
#define NTP_UPDATED_FILE "/tmp/ntp_updated"
#define DDNS_UPDATED_TILE "/tmp/ez-ipupd.status"

int g_ntp_updated = 0;
int g_ntp_sync_times = 0;  /* ntp 同步次数 */

int wan_last_link = -1;

int get_wan_link()
{
	FILE *fp = NULL;
	int link;
	
	fp = fopen(LINK_STATUS_FILE, "r");
	if (!fp)
	{
		return WAN_ERR;
	}
	
	link = fgetc(fp);

    fclose(fp);
    
	return (link - '0');
}

/* status = 1 更新成功，其他失败 */
int get_ddns_status()
{
    int status;
    FILE *fp = NULL;
	
	fp = fopen(DDNS_UPDATED_TILE, "r");
	if (!fp)
	{
		return -1;
	}
	
	status = fgetc(fp);

    fclose(fp);
    
	return (status - '0');
}

void ntp_up_event()
{
    pid_t pid;

    pid = fork();
    if (pid < 0)
    {   
        return ; 
    }   
    else if (pid == 0)
    {   
        if (execl("/usr/sbin/ipsec", "ipsec", "restart", NULL) < 0)
        {   
            fprintf(stderr, "execl: %s\n", strerror(errno));
        }
    }    
}

void ddns_up_event()
{
    pid_t pid;

    pid = fork();
    if (pid < 0)
    {   
        return ; 
    }   
    else if (pid == 0)
    {   
        if (execl("/usr/sbin/ct_ipsec.sh", "ct_ipsec.sh", "reload", NULL) < 0)
        {   
            fprintf(stderr, "execl: %s\n", strerror(errno));
        }
    }    
}

void wan_down_event()
{
    pid_t pid;

    pid = fork();
    if (pid < 0)
    {   
        return ; 
    }   
    else if (pid == 0)
    {   
        if (execl("/usr/sbin/ipsec", "ipsec", "stop", NULL) < 0)
        {   
            fprintf(stderr, "execl: %s\n", strerror(errno));
        }   
    }
}

void trigger_wan_event(int link)
{
    if ((link != wan_last_link) && (link == WAN_UP))
    {
        fprintf(stdout, "WAN link up.\n");
    }

    if (link != wan_last_link && link == WAN_DOWN)
    {
        fprintf(stdout, "WAN link down.\n");
        wan_down_event();    
    }

    wan_last_link = link;
}

void trigger_ddns_event(int status)
{
    if (status == 1)
    {
        /* 重启ipsec */
        ddns_up_event();
    }
}

int link_event_notify()
{
    int fd, wd;

    fd = inotify_init();
    if (fd < 0)
    {
        fprintf(stderr, "inotify_init failed\n");
        return -1;
    }

    wd = inotify_add_watch(fd, LINK_STATUS_FILE, IN_ALL_EVENTS);
    if (wd < 0)
    {
        fprintf(stderr, "inotify_add_watch %s failed\n", LINK_STATUS_FILE);
        return -1;
    }

    return fd;
}

int ddns_event_notify()
{
    int fd, wd;

    fd = inotify_init();
    if (fd < 0)
    {
        fprintf(stderr, "inotify_init failed\n");
        return -1;
    }

    wd = inotify_add_watch(fd, DDNS_UPDATED_TILE, IN_ALL_EVENTS);
    if (wd < 0)
    {
        fprintf(stderr, "inotify_add_watch %s failed\n", DDNS_UPDATED_TILE);
        return -1;
    }

    return fd;    
}

int link_event_recv(int fd)
{
    int len = 0;
    int nread = 0;
    char buf[BUFSIZ] = {0};
    struct inotify_event *event;

    buf[sizeof(buf) - 1] = 0;
    len = read(fd, buf, sizeof(buf) - 1);
    {
        nread = 0;
        while (len > 0)
        {
            event = (struct inotify_event *)&buf[nread];

            if (event->mask & IN_CLOSE_WRITE)
            {
                trigger_wan_event(get_wan_link());
            }

            nread = nread + sizeof(struct inotify_event) + event->len;
            len = len - sizeof(struct inotify_event) - event->len;
        }
    }

    return 0;
}

int ddns_event_recv(int fd)
{
    int len = 0;
    int nread = 0;
    char buf[BUFSIZ] = {0};
    struct inotify_event *event;

    buf[sizeof(buf) - 1] = 0;
    len = read(fd, buf, sizeof(buf) - 1);
    {
        nread = 0;
        while (len > 0)
        {
            event = (struct inotify_event *)&buf[nread];

            if (event->mask & IN_CLOSE_WRITE)
            {
                trigger_ddns_event(get_ddns_status());
            }

            nread = nread + sizeof(struct inotify_event) + event->len;
            len = len - sizeof(struct inotify_event) - event->len;
        }
    }    

    return 0;
}

void monitor_loop()
{
    int ret;
    int max_fd;
    fd_set rfds;
    struct timeval tv;
    int link_wd = -1;
    int ddns_wd = -1;

    link_wd = link_event_notify();
    if (link_wd < 0)
    {
        goto out;
    }
    
    ddns_wd = ddns_event_notify();
    if (ddns_wd < 0)
    {
        goto out;
    }

    max_fd = (link_wd > ddns_wd) ? link_wd : ddns_wd;

    while (1)
    {
        tv.tv_sec = 10;
        tv.tv_usec = 0;
        
        FD_ZERO(&rfds);                    
        FD_SET(link_wd, &rfds);
        FD_SET(ddns_wd, &rfds);

        ret = select(max_fd + 1, &rfds, NULL, NULL, &tv);
        if(ret < 0)
        {   
            if(errno == EINTR)
            {   
                continue;
            }   
                
            fprintf(stderr, "select: %s", strerror(errno));
            
            break;
        }   
        else if(ret == 0)
        {   
            continue;
        }

        if (link_wd > 0)
        {
            /* Link状态变化 */
            if (FD_ISSET(link_wd, &rfds))
            {
                ret = link_event_recv(link_wd);
                if (ret < 0)
                {
                    fprintf(stderr, "link event recv failed!\n");
                }
            }
        }
        
        if (ddns_wd > 0)
        {
            /* ddns状态变化 */
            if (FD_ISSET(ddns_wd, &rfds))
            {            
                ret = ddns_event_recv(ddns_wd);
                if (ret < 0)
                {
                    fprintf(stderr, "ddns event recv failed!\n");
                }
            }
        }
    }

out:
    if (link_wd > 0)
    {
        close(link_wd);
    }

    if (ddns_wd > 0)
    {
        close(ddns_wd);
    }
}

void sig_child(int signo)
{
    pid_t pid;
    int status;

    while((pid = waitpid(-1, &status, WNOHANG)) > 0); 

    return;
}

void sig_ntp_updated(int signo)
{
    if (g_ntp_updated != 0)
    {
        return;
    }

    if ((++ g_ntp_sync_times) == 1)
    {
        ntp_up_event();
    }
}

int main(int argc, char *argv[])
{
    int opt = 0;
    int nodaemon = 0;

    signal(SIGCHLD, sig_child);
    signal(SIGUSR1, sig_ntp_updated);

    while((opt = getopt(argc, argv, "fh")) != -1) 
    {   
        switch(opt)
        {   
            case 'f':
                nodaemon = 1;
                break;
            case 'h':
                break;
        }
    }

    if(!nodaemon)
    {
        daemon(0, 0);
    }

    /* 
     * 启动是检查ntpclient是否同步过时间
     */
    if (access(NTP_UPDATED_FILE, F_OK) == 0) 
    {
        g_ntp_updated = 1;
    }

    /* 创建DDNS临时文件 */
    system("touch /tmp/ez-ipupd.status");

    while(1)
    {
        monitor_loop();
        sleep(10);
    }
    
	return 0;
}
