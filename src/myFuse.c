#define FUSE_USE_VERSION 35
#define _GNU_SOURCE

#include <fuse3/fuse.h>
#include <stdio.h>
#include <stdlib.h>     // realpath 함수 사용을 위해 추가
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <dirent.h>
#include <limits.h>
#include <sys/time.h>
#include <signal.h>
#include <pthread.h> // 뮤텍스 사용
// 추가 include 
#include <sys/types.h>
#include "myFuse.h"
#include "entropy.h"
#include "log.h"

// ===========================================================================
//                          추가 전역 변수 & 구조체 정의
// ===========================================================================

// 옵션 파싱을 위한 구조체
struct myfs_config {
    int log_enabled; // --log 옵션이 들어오면 1이 됨
};
static struct myfs_config conf;

// FUSE 옵션 정의 매크로
#define MYFS_OPT(t, p, v) { t, offsetof(struct myfs_config, p), v }

static const struct fuse_opt myfs_opts[] = {
    MYFS_OPT("--log", log_enabled, 1), // --log 옵션이 있으면 conf.log_enabled = 1
    FUSE_OPT_END
};

static int base_fd = -1;

// 전역 변수 및 뮤텍스
ProcessMonitorEntry g_score_table[100]; // MAX_TRACKED_PIDS 대신 100 하드코딩 (헤더 의존성 줄임)
static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER; // 통합 락

// --- 허니팟 리스트 ---
static const char *honeypot_files[] = {
    "secret.txt"
};

// 전역 Score 테이블
ProcessMonitorEntry g_score_table[MAX_TRACKED_PIDS];
int g_proc_cnt = 0; // 현재 추적 중인 프로세스 개수

// 블랙리스트 생성(해당 이름의 파일을 차단)
static const char *blacklist[] = {
    "/ransomware.exe",
    NULL // 목록 끝을 표시
};

/*
    FUSE 시스템의 규칙은 일반적인 사용에 제약이 생길 정도로 규제를 강하게 하면 안됨.
    근데 화이트리스트는 아무리 생각해도 이 규칙 안에서는 큰 의미 없는 것 같음. 
*/
// 쓰기 전용 화이트리스트 생성(일종의 낚시 파일을 제외한 리스트)
// 사용 X
static const char *writable_whitelist[] = {
    "text.txt",  //일반적인 파일 지정
    NULL 
};

// ===========================================================================
//                                 honeypot 함수 
// ===========================================================================

static int is_honeypot(const char *path) {
    for (int i = 0; honeypot_files[i] != NULL; i++) {
        // 경로 안에 해당 파일명이 포함되어 있는지 확인
        if (strstr(path, honeypot_files[i]) != NULL) {
            fprintf(stderr, "[DEBUG] Honeypot DETECTED! Path: %s matched keyword: %s\n", path, honeypot_files[i]);
            return 1;
        }
    }
    // 디버깅용: 허니팟이 아니라고 판단될 때
    // fprintf(stderr, "[DEBUG] Not a honeypot: %s\n", path); 
    return 0;
}

// ===========================================================================
//                                   analyze 함수 
// ===========================================================================

// 해당 파일이 블랙리스트에 포함되는지 확인
static int is_blacklisted(const char *path) {
    for (int i = 0; blacklist[i] != NULL; i++) {
        if (strcmp(path, blacklist[i]) == 0) {
            return 1; // 차단
        }
    }
    return 0; // 허용
}

// 해당 파일이 화이트리스트에 존재하는 파일인지 확인
static int is_writable_whitelisted(const char *path) {
    for (int i = 0; writable_whitelist[i] != NULL; i++) {
        if (strcmp(path, writable_whitelist[i]) == 0) {
            return 1; // 쓰기 허용
        }
    }
    return 0; // 쓰기 차단
}

// ProcessMonitorEntry를 찾거나 새로 생성해 포인터 반환
ProcessMonitorEntry* find_or_create_score_entry(pid_t pid) {
    // 기존 엔트리 검색
    for (int i = 0; i < g_proc_cnt; i++) {
        if (g_score_table[i].pid == pid) { // PID가 이미 존재하면 해당 엔트리 반환
            return &g_score_table[i];
	    }
    }
    
    // 새 엔트리 생성
    if (g_proc_cnt < MAX_TRACKED_PIDS) {
        ProcessMonitorEntry *new_entry = &g_score_table[g_proc_cnt];
        // 새로운 엔트리 초기화
        new_entry->pid = pid;
        new_entry->malice_score = 0;
        new_entry->last_write_time = 0; // 처음엔 0으로 초기화
        new_entry->start_time = 0;      // 0으로 초기화 (첫 호출 시 설정됨)
        new_entry->write_count = 0;
        new_entry->unlink_count = 0;
        new_entry->rename_count = 0;
        g_proc_cnt++; // 추적 중인 프로세스 수 증가
        return new_entry;
    }
    
    // 배열이 가득 찼을 때 
    fprintf(stderr, "오류: 최대 PID 추적 개수 초과!\n");
    return NULL;
}

// 특정 PID의 Malice Score 업데이트, 마지막 쓰기 시간 갱신
void update_malice_score(pid_t pid, int added_score) {
    ProcessMonitorEntry *entry = find_or_create_score_entry(pid);
    
    if (entry) {
        entry->malice_score += added_score;
        entry->last_write_time = time(NULL); 
    }
}

// 특정 PID의 Malice Score 반환
int get_malice_score(pid_t pid) {
    ProcessMonitorEntry *entry = find_or_create_score_entry(pid);
    if (entry) {
        return entry->malice_score;
    }
    return 0; // 엔트리 못 찾으면 0점 반환
}

/**
 * @brief 지정된 경로(base_path)로부터 모든 하위 파일과 디렉터리를 재귀적으로 순회
 * @param base_path 탐색을 시작할 디렉터리 경로
 */
// 프로세스 종료 시 Score 0으로 초기화
// 이거 그냥 리스트에서 제거해야 되는거 아님?
void reset_malice_score(pid_t pid) {
    ProcessMonitorEntry *entry = find_or_create_score_entry(pid);
    if (entry) {
        entry->malice_score = 0;
    }
}

// ===========================================================================
//                              analyzer.c 함수 병합 
// ===========================================================================

/**
 * @brief 연산 내용에 따라 1회 점수를 계산 (엔트로피 비교 포함)
 * @param operation 연산
 * @param buf 사용자 쓰기 입력 버퍼
 * @param size 버퍼 크기
 * @param entropy_before 쓰기 전 원본 데이터의 엔트로피
 */
static int calc_score(const char* operation, const char* buf, size_t size, double entropy_before) {
    int score_to_add = 0;

    if (strcmp(operation, "WRITE") == 0) {
        score_to_add += WEIGHT_WRITE; // 1점 추가

        if (buf != NULL && size > 0) {
            double entropy_after = calculate_entropy(buf, size); // 쓰기 후 엔트로피
            
            // 엔트로피가 임계값을 넘고, 이전보다 '증가'했을 때
            if (entropy_after > ENTROPY_THRESHOLD && entropy_after > entropy_before) {
                score_to_add += WEIGHT_HIGH_ENTROPY; // 5점 추가
                fprintf(stderr, "PID %d: High entropy detected (Before: %.2f, After: %.2f)\n", 
                        fuse_get_context()->pid, entropy_before, entropy_after);
            }
        }
    }
    else if (strcmp(operation, "UNLINK") == 0 || strcmp(operation, "RENAME") == 0) {
        score_to_add += WEIGHT_MALICIOUS; // 3점 추가
    }
    return score_to_add;
}

/**
 * @brief 1초마다 빈도를 검사하고, 누적 점수로 최종 악성 여부 판단
 * @param entry 현재 PID에 해당하는 ProcessMonitorEntry 포인터
 */
static int check_frequency_and_alert(ProcessMonitorEntry* entry) {
    time_t current_time = time(NULL);
    int is_malicious = 0; // 1: 악성

    if(entry->start_time == 0) { // 첫 호출
        entry->start_time = current_time;
        // 첫 호출 시에도 최종 점수 검사는 필요함
    }

    // 1초가 경과 확인
    if (current_time - entry->start_time >= TIME_SECONDS) {
        // 빈도수 검사 및 벌점 부과
        if (entry->write_count > WRITE_THRESHOLD_PER_1) {
            entry->malice_score += PENALTY_HIGH_WRITE;
        }
        if (entry->unlink_count > UNLINK_THRESHOLD_PER_1) {
            entry->malice_score += PENALTY_HIGH_UNLINK;
        }
        if (entry->rename_count > RENAME_THRESHOLD_PER_1) {
            entry->malice_score += PENALTY_HIGH_RENAME;
        }

        // 카운트 리셋
        entry->write_count = 0;
        entry->unlink_count = 0;
        entry->rename_count = 0;
        // 타이머 리셋
        entry->start_time = current_time; 
    }

    // 누적된 총 점수가 임계치를 넘는지 검사 (기존 KILL_THRESHOLD 대신 사용)
    if (entry->malice_score > FINAL_MALICE_THRESHOLD) {
        printf("malice detected (PID:%d)\n", entry->pid); 
        printf("malice score : %d (threshold: %d)\n", entry->malice_score, FINAL_MALICE_THRESHOLD);
        
        // 1초가 리셋되기 직전의 카운트를 보여줌
        printf("현재 1초간 행동 횟수 :(w : %d. U : %d, R:%d)\n", entry->write_count, entry->unlink_count, entry->rename_count);

        is_malicious = 1; // 악성으로 판정
    }
    
    return is_malicious;
}

/**
 * @brief 메인 모니터링 함수 (FUSE 훅에서 호출됨)
 * @param operation 연산
 * @param buf 사용자 입력 버퍼
 * @param size 입력 버퍼 크기
 * @param entropy_before (WRITE용) 쓰기 전 엔트로피
 */
static int monitor_operation(const char* operation, const char* path, const char* buf, size_t size, double entropy_before) {
    pthread_mutex_lock(&g_lock); // 동기화 시작

    struct fuse_context *context = fuse_get_context();
    pid_t current_pid = context->pid;

    ProcessMonitorEntry *entry = find_or_create_score_entry(current_pid);
    if (!entry) {
        fprintf(stderr, "PID %d: Failed to get score entry (table full?)\n", current_pid);
        return 0; // 추적 테이블이 가득 차면 방어 실패 (일단 허용)
    }

    // 1. 개별 연산 점수 계산 및 누적
    int score_to_add = calc_score(operation, buf, size, entropy_before);
    // 허니팟 체크
    if (is_honeypot(path)) {
        fprintf(stderr, "!!! HONEYPOT TOUCHED: %s by PID %d !!!\n", path, current_pid);
        score_to_add += (FINAL_MALICE_THRESHOLD + 1); // 즉사 수준 점수 부여
    }
    entry->malice_score += score_to_add;

    // 2. 빈도수 카운트 누적
    if (strcmp(operation, "WRITE") == 0) {
        entry->write_count++;
        entry->last_write_time = time(NULL); // 마지막 쓰기 시간 갱신
    } else if (strcmp(operation, "UNLINK") == 0) {
        entry->unlink_count++;
    } else if (strcmp(operation, "RENAME") == 0) {
        entry->rename_count++;
    }

    // 3. 로그 기록
    double entropy_after = calculate_entropy(buf, size);
    log_activity(current_pid, operation, path, entropy_before, entropy_after, score_to_add, entry->malice_score);

    pthread_mutex_unlock(&g_lock); // 동기화 종료

    // 4. 1초 윈도우 검사 및 최종 악성 여부 반환
    return check_frequency_and_alert(entry);
}

// ===========================================================================
//                          FUSE File System 기본 함수 
// ===========================================================================

// 절대 경로를 상대 경로로 변경
static void get_relative_path(const char *path, char *relpath) {
    if (strcmp(path, "/") == 0 || strcmp(path, "") == 0) {
        strcpy(relpath, ".");
    } else {
        if (path[0] == '/')
            path++;
        strncpy(relpath, path, PATH_MAX);
    }
}

// 파일이나 디렉터리의 속성 정보 제공
static int myfs_getattr(const char *path, struct stat *stbuf, struct fuse_file_info *fi) {
    (void) fi;
    int res;
    char relpath[PATH_MAX];
    get_relative_path(path, relpath);

    res = fstatat(base_fd, relpath, stbuf, AT_SYMLINK_NOFOLLOW);
    if (res == -1)
        return -errno;
    
    // 블랙리스트 기반 차단
    if ((stbuf->st_mode & S_IFREG) && (stbuf->st_mode & (S_IXUSR | S_IXGRP | S_IXOTH))) {
        // 블랙리스트에 존재 여부 검사
        if (is_blacklisted(path)) {
            // 존재하면 실행에 대한 권한 강제 제거
            stbuf->st_mode &= ~(S_IXUSR | S_IXGRP | S_IXOTH);
        }
    }

    return 0;
}

// readdir 함수 구현
static int myfs_readdir(const char *path, void *buf, fuse_fill_dir_t filler, off_t offset, struct fuse_file_info *fi, enum fuse_readdir_flags flags) {
    DIR *dp;
    struct dirent *de;
    int fd;

    (void) offset;
    (void) fi;
    (void) flags;

    char relpath[PATH_MAX];
    get_relative_path(path, relpath);

    fd = openat(base_fd, relpath, O_RDONLY | O_DIRECTORY);
    if (fd == -1)
        return -errno;

    dp = fdopendir(fd);
    if (dp == NULL) {
        close(fd);
        return -errno;
    }

    while ((de = readdir(dp)) != NULL) {
        struct stat st;
        memset(&st, 0, sizeof(st));
        st.st_ino = de->d_ino;
        st.st_mode = de->d_type << 12;
        if (filler(buf, de->d_name, &st, 0, 0))
            break;
    }

    closedir(dp);
    return 0;
}

// open 함수 구현
static int myfs_open(const char *path, struct fuse_file_info *fi) {
    // 쓰기 검사 구현
    // if ((fi->flags & O_WRONLY) || (fi->flags & O_RDWR)) {
    //     // 화이트리스트에 있는지 확인
    //     if (!is_writable_whitelisted(path)) {
    //         return -EACCES; //없다면 접근 거부
    //     }
    // }

    int res;
    char relpath[PATH_MAX];
    get_relative_path(path, relpath);

    res = openat(base_fd, relpath, fi->flags);
    if (res == -1)
        return -errno;

    fi->fh = res;
    return 0;
}

// create 함수 구현
static int myfs_create(const char *path, mode_t mode, struct fuse_file_info *fi) {
    // 쓰기(생성) 차단
    // if (!is_writable_whitelisted(path)) {
    //     return -EACCES; 
    // }

    int res;
    char relpath[PATH_MAX];
    get_relative_path(path, relpath);

    res = openat(base_fd, relpath, fi->flags | O_CREAT, mode);
    if (res == -1)
        return -errno;

    fi->fh = res;
    return 0;
}

// read 함수 구현
static int myfs_read(const char *path, char *buf, size_t size, off_t offset, struct fuse_file_info *fi) {
    int res;

    res = pread(fi->fh, buf, size, offset);
    if (res == -1)
        res = -errno;

    return res;
}

// write 함수 구현
static int myfs_write(const char *path, const char *buf, size_t size, off_t offset, struct fuse_file_info *fi) {
    // 화이트리스트 체크
    // if (!is_writable_whitelisted(path)) { // 화이트리스트에 없으면 접근 거부
    //     return -EACCES; 
    // }
    
    // 1. 원본 데이터 읽기 및 '쓰기 전' 엔트로피 계산
    char *original_buf = malloc(size);
    double entropy_before = 0;
    if (original_buf != NULL) {
        ssize_t read_bytes = pread(fi->fh, original_buf, size, offset);
        if (read_bytes > 0) {
            entropy_before = calculate_entropy(original_buf, read_bytes);
        }
        free(original_buf);
    } else {
        // 메모리 할당 실패 시, 엔트로피 검사 스킵
        fprintf(stderr, "Warning: Failed to allocate buffer for entropy check.\n");
    }

    // 2. 통합 모니터링 함수 호출
    int is_malicious = monitor_operation("WRITE", path, buf, size, entropy_before);
    
    // 3. 악성 행위 차단
    if (is_malicious) {
        fprintf(stderr, "Kill ! 'write' 임계값 초과! PID %d 강제 종료\n", fuse_get_context()->pid);
        
        if (kill(fuse_get_context()->pid, SIGKILL) == -1) {
            fprintf(stderr, "킬 명령어 실패: %s\n", strerror(errno));
        }
        return -EIO; // 쓰기 연산 차단
    }

    // 정상 연산 
    int res;
    res = pwrite(fi->fh, buf, size, offset);
    if (res == -1) {
        res = -errno;
    }
    return res;
}

// release 함수 구현
static int myfs_release(const char *path, struct fuse_file_info *fi) {
    close(fi->fh);
    struct fuse_context *context = fuse_get_context();
    pid_t current_pid = context->pid;

    //파일 닫으면 해당 p의 score초기화 -> why?
    // reset_malice_score(current_pid); 
    return 0;
}

// unlink 함수 구현 (파일 삭제)
static int myfs_unlink(const char *path) {
    // 화이트리스트 체크
    // if (!is_writable_whitelisted(path)) {
    //     return -EACCES; // 화이트리스트에 없으면 삭제 거부
    // }
    
    // 1. 통합 모니터링 함수 호출 (엔트로피 불필요, 0 전달)
    int is_malicious = monitor_operation("UNLINK", NULL, NULL, 0, 0);

    // 2. 악성 행위 차단
    if (is_malicious) {
        fprintf(stderr, "Kill ! 'unlink' 임계값 초과! PID %d 강제종료\n", fuse_get_context()->pid);
        if(kill(fuse_get_context()->pid, SIGKILL) == -1){
            fprintf(stderr, " 킬명령어 실패:%s\n", strerror(errno));
        }
        return -EIO; // 삭제 연산 차단
    }

    // 정상 연산
    int res;
    char relpath[PATH_MAX];
    get_relative_path(path, relpath);

    res = unlinkat(base_fd, relpath, 0);
    if (res == -1)
        return -errno;

    return 0;
}

// mkdir 함수 구현 (디렉터리 생성)
static int myfs_mkdir(const char *path, mode_t mode) {
    int res;
    char relpath[PATH_MAX];
    get_relative_path(path, relpath);

    res = mkdirat(base_fd, relpath, mode);
    if (res == -1)
        return -errno;

    return 0;
}

// rmdir 함수 구현 (디렉터리 삭제)
static int myfs_rmdir(const char *path) {
    int res;
    char relpath[PATH_MAX];
    get_relative_path(path, relpath);

    res = unlinkat(base_fd, relpath, AT_REMOVEDIR);
    if (res == -1)
        return -errno;

    return 0;
}

// rename 함수 구현 (파일/디렉터리 이름 변경)
static int myfs_rename(const char *from, const char *to, unsigned int flags) {
    // to 경로에 대한 화이트리스트 체크 (화이트리스트 파일로만 이름 변경 허용)
    // if (!is_writable_whitelisted(to)) {
    //     return -EACCES; // 목적지 경로가 화이트리스트에 없으면 거부
    // }
    
    // 1. 통합 모니터링 함수 호출 (엔트로피 불필요, 0 전달)
    int is_malicious = monitor_operation("RENAME", NULL, NULL, 0, 0);

    // 2. 악성 행위 차단
    if (is_malicious) {
        fprintf(stderr, "Kill ! 'rename' 임계값 초과! PID %d 강제종료\n", fuse_get_context()->pid);
        if(kill(fuse_get_context()->pid, SIGKILL) == -1){
            fprintf(stderr, " 킬명령어 실패:%s\n", strerror(errno));
        }
        return -EIO; // 이름 변경 연산 차단
    }

    // 정상 연산
    int res;
    char relfrom[PATH_MAX];
    char relto[PATH_MAX];
    get_relative_path(from, relfrom);
    get_relative_path(to, relto);

    if (flags)
        return -EINVAL;

    res = renameat(base_fd, relfrom, base_fd, relto);
    if (res == -1)
        return -errno;

    return 0;
}

// utimens 함수 구현
static int myfs_utimens(const char *path, const struct timespec tv[2],
                        struct fuse_file_info *fi) {
    int res;
    char relpath[PATH_MAX];
    get_relative_path(path, relpath);

    if (fi != NULL && fi->fh != 0) {
        // 파일 핸들이 있는 경우
        res = futimens(fi->fh, tv);
    } else {
        // 파일 핸들이 없는 경우
        res = utimensat(base_fd, relpath, tv, 0);
    }
    if (res == -1)
        return -errno;

    return 0;
}

// 파일시스템 연산자 구조체
static const struct fuse_operations myfs_oper = {
    .getattr    = myfs_getattr,
    .readdir    = myfs_readdir,
    .open       = myfs_open,
    .create     = myfs_create,
    .read       = myfs_read,
    .write      = myfs_write,
    .release    = myfs_release,
    .unlink     = myfs_unlink,
    .mkdir      = myfs_mkdir,
    .rmdir      = myfs_rmdir,
    .rename     = myfs_rename,
    .utimens    = myfs_utimens,  
};


int main(int argc, char *argv[]) {
    // fuse_args 구조체 초기화
    struct fuse_args args = FUSE_ARGS_INIT(argc, argv);

    if (args.argc < 2) {
        fprintf(stderr, "Usage: %s [options] <mountpoint>\n", args.argv[0]);
        fuse_opt_free_args(&args); // 메모리 해제 후 종료
        return -1;
    }

    // 설정 구조체 초기화 (기본값 0: 로그 끔)
    memset(&conf, 0, sizeof(conf));

    // 인자 파싱 (FUSE가 --log를 인식하고 conf에 값을 채워줌)
    // 파싱된 인자는 args에 남겨두고, 인식된 커스텀 인자는 처리 후 제거됨
    if (fuse_opt_parse(&args, &conf, myfs_opts, NULL) == -1) {
        fuse_opt_free_args(&args);
        return 1;
    }

    fprintf(stderr, "DEBUG: args.argc = %d\n", args.argc);
    for (int i = 0; i < args.argc; i++) {
        fprintf(stderr, "DEBUG: args.argv[%d] = '%s'\n", i, args.argv[i]);
    }

    // 파싱 결과 적용
    if (conf.log_enabled) {
        set_logging_enabled(1); // Logger 켜기
        fprintf(stderr, "INFO: Logging ENABLED (--log option detected)\n");
    } else {
        set_logging_enabled(0); // Logger 끄기
        fprintf(stderr, "INFO: Logging DISABLED (Default). Use --log to enable.\n");
    }

    // 로그 파일 초기화 (켜져있을 때만 생성됨)
    if (init_log_file() == -1 && conf.log_enabled) {
        fprintf(stderr, "Warning: Failed to initialize log file.\n");
    }

    // 마운트 포인트 경로 저장
    char *mountpoint = realpath(args.argv[args.argc - 1], NULL);
    if (mountpoint == NULL) {
        perror("realpath");
        fuse_opt_free_args(&args);
        return -1;
    }

    // 지정된 경로 획득 (백엔드 경로)
    const char *home_dir = getenv("HOME");
    if (!home_dir) {
    	fprintf(stderr, "Error: HOME environment variable not set.\n");
        fuse_opt_free_args(&args);
        return -1;
    }
    
    char backend_path[PATH_MAX];
    // '/home/계정명/workspace/target' 경로 구성
    snprintf(backend_path, PATH_MAX, "%s/workspace/target", home_dir);

    // 백엔드 디렉터리 열기 (base_fd 획득)
    fprintf(stderr, "INFO: Protecting backend path: %s\n", backend_path);
    
    base_fd = open(backend_path, O_RDONLY | O_DIRECTORY);
    if (base_fd == -1) {
        perror("Error opening backend directory");
        fuse_opt_free_args(&args);
        return -1;
    }

    // FUSE 파일시스템 실행
    int ret = fuse_main(args.argc, args.argv, &myfs_oper, NULL);

    fuse_opt_free_args(&args);
    close(base_fd);
    return ret;
}