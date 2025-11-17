#ifndef MYFUSE_H
#define MYFUSE_H

#include <time.h>     // time_t
#include <sys/types.h> // pid_t

// ===========================================================================
//                        가중치 및 임계치 정의 
// ===========================================================================

// --- 개별 행위 가중치 ---
#define WEIGHT_WRITE 1          // myfs_write 호출시 기본 점수 1 
#define WEIGHT_MALICIOUS 3      // myfs_unlink 나 _rename 호출시 점수 3 
#define WEIGHT_HIGH_ENTROPY 5   // 엔트로피 임계값 초과 및 증가 시 5점 추가
#define ENTROPY_THRESHOLD 4.2   // 엔트로피 임계치

// --- 1초당 행위 빈도 임계치 ---
#define TIME_SECONDS 1              // 1초 단위 검사
#define WRITE_THRESHOLD_PER_1 100   // 1초에 write 100회까지
#define UNLINK_THRESHOLD_PER_1 10   // 1초에 unlink 10회까지
#define RENAME_THRESHOLD_PER_1 10   // 1초에 rename 10회까지

// --- 빈도 임계치 초과 시 벌점 ---
#define PENALTY_HIGH_WRITE 50       // 쓰기 100회 넘었을 때 추가 벌점
#define PENALTY_HIGH_UNLINK 100     // 언링크 10회 넘었을 때 추가 벌점
#define PENALTY_HIGH_RENAME 100

// --- 최종 악성 판단 임계치 ---
#define FINAL_MALICE_THRESHOLD 200 // 총 누적 점수가 200이 넘으면 최종 악성 판단


// ===========================================================================
//                          FUSE 관련 정의
// ===========================================================================

#define MAX_TRACKED_PIDS 100 // 최대 추적 PID 개수


// ===========================================================================
//                          핵심 구조체 정의
// ===========================================================================

// PID score, 동작 기록 구조체
typedef struct {
    pid_t pid; 
    int malice_score; // 벌점    

    time_t start_time; // 1초 윈도우 시작 시간
    time_t last_write_time; // 마지막 쓰기 연산 시간 

    // 1초 윈도우 내의 행위 카운트
    int write_count;
    int unlink_count;
    int rename_count;

    char proc_name[32]; //  프로세스 이름 저장
} ProcessMonitorEntry;


#endif // MYFUSE_H