# 1. 변수 설정 (Variables)
# --------------------------

# 컴파일러
CC = gcc

# 컴파일 플래그
# -Isrc : 헤더 파일들이 모두 src 안에 존재
CFLAGS = -Wall -Wextra -g -Isrc `pkg-config fuse3 --cflags`

# 최종 실행 파일 이름
TARGET = myfs

# 링커 플래그 (FUSE3 자동 링크)
LDFLAGS = `pkg-config fuse3 --libs` -lm

# src 디렉터리 안의 모든 .c 파일 자동 검색
SRCS = $(wildcard src/*.c)

# src/*.c → obj/*.o 로 변환
OBJS = $(patsubst src/%.c, obj/%.o, $(SRCS))


# 2. 빌드 규칙 (Recipes)
# -----------------------

.PHONY: all clean run

# 기본 타겟
all: $(TARGET)

# 최종 바이너리 링크
$(TARGET): $(OBJS)
	@echo "Linking..."
	$(CC) $(CFLAGS) -o $(TARGET) $(OBJS) $(LDFLAGS)
	@echo "Build complete: $(TARGET)"

# 오브젝트 파일 생성 규칙
obj/%.o: src/%.c
	@mkdir -p obj
	@echo "Compiling $<..."
	$(CC) $(CFLAGS) -c $< -o $@


# 3. 유틸리티 규칙
# -----------------

clean:
	@echo "Cleaning up..."
	rm -f $(TARGET)
	rm -rf obj

run: all
	./$(TARGET)
