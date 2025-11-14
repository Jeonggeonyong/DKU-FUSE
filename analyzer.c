#include <math.h>
#include <string.h>
#include <stddef.h>
#include <time.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h> // pid_t

#include "analyzer.h"
#include "entropy.h"


// --- 전역 상태 변수 ---
static int write_count = 0;
static int unlink_count = 0;
static int rename_count = 0;
static int total_malice_score = 0;
static time_t start_time = 0;


/**
 * @brief 연산 내용에 따라 1회 점수를 계산
 * @param operation 연산
 * @param buf 사용자 쓰기 입력 버퍼
 * @param size 버퍼 크기
 */
int calc_score(const char* operation, const char* buf, size_t size) {
    int score_to_add = 0;

    if (strcmp(operation, "WRITE") == 0) {
        score_to_add += WEIGHT_WRITE; // 1점 추가

        // 단순 엔트로피 임계값 초과 확인 로직 -> write 이전 이후 엔트로피 계산하는 방식으로 수정 필요
        if (buf != NULL && size > 0) {
            double entropy = calculate_entropy(buf, size); // 엔트로피 검사
            if (entropy > ENTROPY_THRESHOLD) {
                score_to_add += WEIGHT_HIGH_ENTROPY; // 5점 추가
            }
        }
    }
    else if (strcmp(operation, "UNLINK") == 0 || strcmp(operation, "RENAME") == 0) {
        score_to_add += WEIGHT_MALICIOUS; // 3점 추가
    }
    return score_to_add; // write, rename, unlink 만 점수 부여
}

/**
 * @brief 1초마다 빈도를 검사하고, 누적 점수로 최종 악성 여부 판단
 * @param current_pid 현재 PID
 */
static int check_frequency_and_alert(pid_t current_pid) {
    time_t current_time = time(NULL);
    int is_malicious = 0; // 1: 악성

    if(start_time == 0) { // 첫 호출
        start_time = current_time;
        return 0; // 첫 호출은 1초 대기
    }

    // 1초가 경과 확인
    if (current_time - start_time >= TIME_SECONDS) {
        // 빈도수 검사 및 벌점 부과
        if (write_count > WRITE_THRESHOLD_PER_1) {
            total_malice_score += PENALTY_HIGH_WRITE;
        }
        if (unlink_count > UNLINK_THRESHOLD_PER_1) {
            total_malice_score += PENALTY_HIGH_UNLINK;
        }
        if (rename_count > RENAME_THRESHOLD_PER_1) {
            total_malice_score += PENALTY_HIGH_RENAME;
        }

        // 카운트 리셋
        write_count = 0;
        unlink_count = 0;
        rename_count = 0;
        // 타이머 리셋
        start_time = current_time; 
    }

    // 누적된 총 점수가 임계치를 넘는지 검사
    if (total_malice_score > FINAL_MALICE_THRESHOLD) {
        printf("malice detected (PID:%d)\n", current_pid); 
        printf("malice score : %d (threshold: %d)\n", total_malice_score, FINAL_MALICE_THRESHOLD);
        
        // 이 횟수는 1초 윈도우가 리셋된 직후라면 0일 수 있음
        printf("현재 1초간 행동 횟수 :(w : %d. U : %d, R:%d)\n", write_count, unlink_count, rename_count);

        is_malicious = 1; // 악성으로 판정

        // [선택적 로직] 
        // 한 번 탐지된 PID를 계속 차단하려면 점수를 0으로 리셋하면 안 됩니다.
        // 만약 한 번 경고 후 리셋하려면 아래 주석을 해제하세요.
        // total_malice_score = 0; 
    }
    
    // 1초가 지나지 않았더라도 항상 is_malicious 값을 반환
    return is_malicious;
}

/**
 * @brief 메인 모니터링 함수
 * @param operation 연산
 * @param buf 사용자 입력 버퍼
 * @param size 입력 버퍼 크기
 * @param current_pid 현재 PID 
 */
int monitor_operation(const char* operation, const char* buf, size_t size, pid_t current_pid) {
    // 개별 연산 점수 계산 및 누적
    int content_score = calc_score(operation, buf, size);
    total_malice_score += content_score;

    // 빈도수 카운트 누적
    if (strcmp(operation, "WRITE") == 0) {
        write_count++;
    } else if (strcmp(operation, "UNLINK") == 0) {
        unlink_count++;
    } else if (strcmp(operation, "RENAME") == 0) {
        rename_count++;
    }

    // PID를 check_frequency_and_alert로 전달하여 악성 여부 검사
    return check_frequency_and_alert(current_pid);
}