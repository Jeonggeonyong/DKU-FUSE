// static char backend_root_path[PATH_MAX]; // 섀도우 카피용 절대 경로

// ===========================================================================
//                                 섀도우 카피 함수
// ===========================================================================

// static int create_shadow_copy(const char *relpath) {
//     char src_path[PATH_MAX];
//     char dest_path[PATH_MAX];
//     char shadow_dir[PATH_MAX];

//     // 1) 경로 구성
//     snprintf(src_path, PATH_MAX, "%s/%s", backend_root_path, relpath);
//     snprintf(shadow_dir, PATH_MAX, "%s/.shadow", backend_root_path);
    
//     // 디렉토리 구조 유지를 안 하고 단순하게 파일명만 백업한다고 가정 (테스트용)
//     // 실제로는 디렉토리 트리 구조도 만들어야 하지만 복잡성을 줄임.
//     // 예: target.txt -> .shadow/target.txt_1732020202.bak
//     char safe_name[PATH_MAX];
//     char *filename = strrchr(relpath, '/');
//     filename = (filename) ? filename + 1 : (char*)relpath;
    
//     snprintf(dest_path, PATH_MAX, "%s/%s_%ld.bak", shadow_dir, filename, time(NULL));

//     // 2) .shadow 폴더 생성 (없으면)
//     mkdir(shadow_dir, 0755);

//     // 3) 파일 복사
//     int fd_src = open(src_path, O_RDONLY);
//     if (fd_src < 0) return 0; // 원본이 없거나 못 열면 스킵

//     int fd_dest = open(dest_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
//     if (fd_dest < 0) {
//         close(fd_src);
//         return 0;
//     }

//     char buf[4096];
//     ssize_t n;
//     while ((n = read(fd_src, buf, sizeof(buf))) > 0) {
//         write(fd_dest, buf, n);
//     }

//     close(fd_src);
//     close(fd_dest);
//     // fprintf(stderr, "[ShadowCopy] Created: %s\n", dest_path);
//     return 1;
// }