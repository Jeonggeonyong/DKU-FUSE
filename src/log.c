#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <limits.h>

#include "log.h"


char log_file_path[PATH_MAX];
// 로그 활성화 상태 (0: OFF, 1: ON) - 기본값 OFF (성능 위해)
static int g_is_enabled = 0;

// 외부에서 이 함수를 호출해 로그를 켤 수 있음
void set_logging_enabled(int enable) {
    g_is_enabled = enable;
}

// 로그 파일 초기화 (CSV 헤더 작성)
int init_log_file(void) {
    // 로그가 꺼져있으면 파일 생성도 안 함
    if (!g_is_enabled) return -1;

    // [/home/user/workspace/fuse_activity.csv]으로 고정
    // HOME 환경변수 기준으로 경로 지정
    const char *home_dir = getenv("HOME");
    if (!home_dir) {
        fprintf(stderr, "Error: HOME environment variable not set.\n");
        return -1;
    }
    

    if (snprintf(log_file_path, sizeof(log_file_path),
             "%s/workspace/%s", home_dir, LOG_FILE_NAME) >= (int)sizeof(log_file_path)) {
        fprintf(stderr, "Error: Target path is too long.\n");
        return -1;
    }

    FILE* fp = fopen(log_file_path, "w");
    if (fp) {
        fprintf(fp, "Time,PID,Operation,File,EntropyBefore,EntropyAfter,AddedScore,TotalScore\n");
        fclose(fp);
    }

    return 0;
}

// 활동 기록 함수
void log_activity(pid_t pid, const char *op, const char *filename, 
                  double ent_before, double ent_after, int score_added, int total_score) {
    FILE *fp = fopen(log_file_path, "a");
    if (fp == NULL) return;

    time_t now = time(NULL);
    struct tm *t = localtime(&now);
    char time_str[64];
    strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", t);

    fprintf(fp, "%s,%d,%s,%s,%.2f,%.2f,%d,%d\n", 
            time_str, pid, op, filename, ent_before, ent_after, score_added, total_score);
    
    fclose(fp);
}


