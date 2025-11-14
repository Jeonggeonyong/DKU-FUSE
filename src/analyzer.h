#ifndef ANALYZER_H
#define ANALYZER_H

// --- 가중치 및 임계치 정의 ---
#define WEIGHT_WRITE 1          // myfs_write 호출시 기본 점수 1 
#define WEIGHT_MALICIOUS 3      // myfs_unlink 나 _rename 호출시 점수 3 
#define WEIGHT_HIGH_ENTROPY 5   // 엔트로피 4.2 이상이면 5점 추가
#define ENTROPY_THRESHOLD 4.2   // 대략적으로 정한 엔트로피 임계치

// 반복 행위에 대한 (빈도에 따라) 임계치
#define TIME_SECONDS 1          // 1초 단위 검사
#define WRITE_THRESHOLD_PER_1 100 // 1초에 write 100회까지
#define UNLINK_THRESHOLD_PER_1 10 // 1초에 unlink 10회까지
#define RENAME_THRESHOLD_PER_1 10 // 1초에 rename 10회까지

// 빈도가 임계치 넘었을 때 추가 벌점
#define PENALTY_HIGH_WRITE 50     // 쓰기 100회 넘었을 때 추가로 벌점 부여
#define PENALTY_HIGH_UNLINK 100   // 언링크 10회 넘었을 때 추가 벌점
#define PENALTY_HIGH_RENAME 100

#define FINAL_MALICE_THRESHOLD 200 // 총 누적 점수가 200이 넘으면 최종 악성 판단

int calc_score(const char* operation, const char* buf, size_t size);
int monitor_operation(const char* operation, const char* buf, size_t size, pid_t current_pid);
int check_frequency_and_alert(pid_t current_pid);
#endif