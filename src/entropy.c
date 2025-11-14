#include <math.h>
#include <string.h>
#include <stddef.h>

// 섀넌 엔트로피 계산 공식
double calculate_entropy(const char *buffer, size_t size){
    if (size == 0) { // 데이터의 크기가 0이면 계산 패스
        return 0.0;
    }

    long long ascii_cnt[256]; // 0 ~ 255 등장 횟수 저장
    memset(ascii_cnt, 0, sizeof(ascii_cnt)); // 배열 초기화
    for (size_t i = 0; i < size; i++){ 
        // if (buffer[i] == 65('A')) then ascii_cnt[65] += 1
        ascii_cnt[(unsigned char) buffer[i]]++; //unsigned -> 음수값 제거
    } 

    // 엔트로피 계산
    double entropy = 0.0; 
    for (int i = 0; i < 256; i++){
        if (ascii_cnt[i] == 0){ // 바이트값이 데이터에 한 번도 등장하지 않으면 확률 p = 0, 즉 연산 X
            continue;
        }
        
        double probability = (double)ascii_cnt[i] / size;
        entropy -= probability * log2(probability); // 엔트로피 공식에 의해 각 바이트를 누적한 최종 엔트로피 계산
    }
    return entropy;
}

