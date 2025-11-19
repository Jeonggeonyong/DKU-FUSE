#ifndef LOG_H
#define LOG_H

#include <sys/types.h> // pid_t 사용

#define LOG_FILE_NAME "fuse_activity.csv"


void set_logging_enabled(int enable); // 로그 ON/OFF 설정 함수
int init_log_file(void);
void log_activity(pid_t pid, const char *op, const char *filename, double ent_before, double ent_after, int score_added, int total_score);


#endif