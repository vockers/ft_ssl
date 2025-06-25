#include <criterion/criterion.h>
#include <criterion/redirect.h>
#include <signal.h>
#include <stdarg.h>

#include "../include/ft_ssl.h"

#include "libft.h"

void test_hash_str(const char* str,
                   const char* expected,
                   usize       digest_size,
                   void (*hash_func)(const char*, usize, u8*))
{
    u8   digest[WHIRLPOOL_DIGEST_SIZE];
    char digest_str[WHIRLPOOL_DIGEST_SIZE * 2 + 1];

    hash_func(str, ft_strlen(str), digest);
    for (size_t i = 0; i < digest_size; i++) {
        sprintf(digest_str + i * 2, "%02x", digest[i]);
    }
    digest_str[digest_size * 2] = '\0';

    cr_assert_str_eq(
        digest_str, expected, "Hash '%s' does not match expected '%s'\n", digest_str, expected);
}

int run_hash_cmd(const char* cmd, ...)
{
    va_list args;

    va_start(args, cmd);
    int   argc = 0;
    char* argv[10];

    while ((argv[argc] = va_arg(args, char*)) != NULL) {
        argc++;
        if (argc >= 10) {
            cr_assert_fail("Too many arguments for command");
            break;
        }
    }

    va_end(args);

    return cmd_hash(argc, argv);
}

#define TEST_MD5(str, expected)    test_hash_str(str, expected, MD5_DIGEST_SIZE, md5_str)
#define TEST_SHA256(str, expected) test_hash_str(str, expected, SHA256_DIGEST_SIZE, sha256_str)
#define TEST_WHIRLPOOL(str, expected) \
    test_hash_str(str, expected, WHIRLPOOL_DIGEST_SIZE, whirlpool_str)

#define RUN_HASH_CMD(...) run_hash_cmd(NULL, __VA_ARGS__, NULL)

void redirect_std(void)
{
    cr_redirect_stdout();
    cr_redirect_stderr();
}

Test(md5, test_md5)
{
    TEST_MD5("", "d41d8cd98f00b204e9800998ecf8427e");
    TEST_MD5("Hello, World!", "65a8e27d8879283831b664bd8b7f0ad4");
    TEST_MD5("The quick brown fox jumps over the lazy dog", "9e107d9d372bb6826bd81d3542a419d6");
    TEST_MD5("The quick brown fox jumps over the lazy dog.", "e4d909c290d0fb1ca068ffaddf22cbd0");
    TEST_MD5("Lorem ipsum dolor sit amet, consectetur adipiscing elit.",
             "35899082e51edf667f14477ac000cbba");
}

Test(md5, test_md5_cmd_stdin, .init = redirect_std)
{
    FILE* f_stdin = cr_get_redirected_stdin();
    fprintf(f_stdin, "Hello, World!");
    fclose(f_stdin);

    RUN_HASH_CMD("md5");
    cr_assert_stdout_eq_str(" (stdin)= 65a8e27d8879283831b664bd8b7f0ad4\n");
}

Test(md5, test_md5_cmd_stdin_p, .init = redirect_std)
{
    FILE* f_stdin = cr_get_redirected_stdin();
    fprintf(f_stdin, "Hello, World!");
    fclose(f_stdin);

    RUN_HASH_CMD("md5", "-p");
    cr_assert_stdout_eq_str(" (\"Hello, World!\")= 65a8e27d8879283831b664bd8b7f0ad4\n");
}

Test(md5, test_md5_cmd_stdin_q, .init = redirect_std)
{
    FILE* f_stdin = cr_get_redirected_stdin();
    fprintf(f_stdin, "Hello, World!");
    fclose(f_stdin);

    RUN_HASH_CMD("md5", "-q");
    cr_assert_stdout_eq_str("65a8e27d8879283831b664bd8b7f0ad4\n");
}

Test(md5, test_md5_cmd_s, .init = redirect_std)
{
    RUN_HASH_CMD("md5", "-s", "Hello, World!");
    RUN_HASH_CMD("md5", "-q", "-s", "Hello, World!");
    RUN_HASH_CMD("md5", "-r", "-s", "Hello, World!");
    RUN_HASH_CMD("md5", "-q", "-r", "-s", "Hello, World!");
    cr_assert_stdout_eq_str("MD5 (\"Hello, World!\") = 65a8e27d8879283831b664bd8b7f0ad4\n"
                            "65a8e27d8879283831b664bd8b7f0ad4\n"
                            "65a8e27d8879283831b664bd8b7f0ad4 \"Hello, World!\"\n"
                            "65a8e27d8879283831b664bd8b7f0ad4\n");
}

Test(md5, test_md5_cmd_file, .init = redirect_std)
{
    RUN_HASH_CMD("md5", "tests/files/file1.txt");
    RUN_HASH_CMD("md5", "-q", "tests/files/file1.txt");
    RUN_HASH_CMD("md5", "-r", "tests/files/file1.txt");
    RUN_HASH_CMD("md5", "-q", "-r", "tests/files/file1.txt");
    cr_assert_stdout_eq_str("MD5 (tests/files/file1.txt) = 65a8e27d8879283831b664bd8b7f0ad4\n"
                            "65a8e27d8879283831b664bd8b7f0ad4\n"
                            "65a8e27d8879283831b664bd8b7f0ad4 tests/files/file1.txt\n"
                            "65a8e27d8879283831b664bd8b7f0ad4\n");
}

Test(md5, test_md5_cmd_file_s, .init = redirect_std)
{
    RUN_HASH_CMD("md5", "-s", "Hello, World!", "tests/files/file2.txt");
    RUN_HASH_CMD("md5", "-q", "-s", "Hello, World!", "tests/files/file2.txt");
    RUN_HASH_CMD("md5", "-r", "-s", "Hello, World!", "tests/files/file2.txt");
    RUN_HASH_CMD("md5", "-q", "-r", "-s", "Hello, World!", "tests/files/file2.txt");
    cr_assert_stdout_eq_str("MD5 (\"Hello, World!\") = 65a8e27d8879283831b664bd8b7f0ad4\n"
                            "MD5 (tests/files/file2.txt) = d41d8cd98f00b204e9800998ecf8427e\n"
                            "65a8e27d8879283831b664bd8b7f0ad4\n"
                            "d41d8cd98f00b204e9800998ecf8427e\n"
                            "65a8e27d8879283831b664bd8b7f0ad4 \"Hello, World!\"\n"
                            "d41d8cd98f00b204e9800998ecf8427e tests/files/file2.txt\n"
                            "65a8e27d8879283831b664bd8b7f0ad4\n"
                            "d41d8cd98f00b204e9800998ecf8427e\n");
}

Test(md5, test_md5_cmd_files, .init = redirect_std)
{
    RUN_HASH_CMD("md5",
                 "-q",
                 "tests/files/file1.txt",
                 "tests/files/file2.txt",
                 "tests/files/file3.txt",
                 "tests/files/file4.txt");
    cr_assert_stdout_eq_str("65a8e27d8879283831b664bd8b7f0ad4\n"
                            "d41d8cd98f00b204e9800998ecf8427e\n"
                            "c6a7779b5a7b3ae0bb0bdd672c98622c\n"
                            "ba413841fb575b59013d38230c171473\n");
}

Test(md5, test_md5_cmd_errors, .init = redirect_std)
{
    RUN_HASH_CMD("md5", "-s");
    RUN_HASH_CMD("md5", "-l");
    RUN_HASH_CMD("md5", "tests/files/unexisting_file", "tests/files/unexisting_file2");
    cr_assert_stderr_eq_str(
        "boxfort-worker: option requires an argument -- 's'\n"
        "boxfort-worker: invalid option -- 'l'\n"
        "boxfort-worker: md5: tests/files/unexisting_file: No such file or directory\n"
        "boxfort-worker: md5: tests/files/unexisting_file2: No such file or directory\n");
}

Test(sha256, test_sha256)
{
    TEST_SHA256("", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    TEST_SHA256("Hello, World!",
                "dffd6021bb2bd5b0af676290809ec3a53191dd81c7f70a4b28688a362182986f");
    TEST_SHA256("The quick brown fox jumps over the lazy dog",
                "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592");
    TEST_SHA256("The quick brown fox jumps over the lazy dog.",
                "ef537f25c895bfa782526529a9b63d97aa631564d5d789c2b765448c8635fb6c");
    TEST_SHA256("Lorem ipsum dolor sit amet, consectetur adipiscing elit.",
                "a58dd8680234c1f8cc2ef2b325a43733605a7f16f288e072de8eae81fd8d6433");
}

Test(sha256, test_sha256_cmd_stdin, .init = redirect_std)
{
    FILE* f_stdin = cr_get_redirected_stdin();
    fprintf(f_stdin, "Hello, World!");
    fclose(f_stdin);

    RUN_HASH_CMD("sha256");
    cr_assert_stdout_eq_str(
        " (stdin)= dffd6021bb2bd5b0af676290809ec3a53191dd81c7f70a4b28688a362182986f\n");
}

Test(sha256, test_sha256_cmd_stdin_p, .init = redirect_std)
{
    FILE* f_stdin = cr_get_redirected_stdin();
    fprintf(f_stdin, "Hello, World!");
    fclose(f_stdin);

    RUN_HASH_CMD("sha256", "-p");
    cr_assert_stdout_eq_str(
        " (\"Hello, World!\")= dffd6021bb2bd5b0af676290809ec3a53191dd81c7f70a4b28688a362182986f\n");
}

Test(sha256, test_sha256_cmd_stdin_q, .init = redirect_std)
{
    FILE* f_stdin = cr_get_redirected_stdin();
    fprintf(f_stdin, "Hello, World!");
    fclose(f_stdin);

    RUN_HASH_CMD("sha256", "-q");
    cr_assert_stdout_eq_str("dffd6021bb2bd5b0af676290809ec3a53191dd81c7f70a4b28688a362182986f\n");
}

Test(sha256, test_sha256_cmd_s, .init = redirect_std)
{
    RUN_HASH_CMD("sha256", "-s", "Hello, World!");
    RUN_HASH_CMD("sha256", "-q", "-s", "Hello, World!");
    RUN_HASH_CMD("sha256", "-r", "-s", "Hello, World!");
    RUN_HASH_CMD("sha256", "-q", "-r", "-s", "Hello, World!");
    cr_assert_stdout_eq_str(
        "SHA256 (\"Hello, World!\") = "
        "dffd6021bb2bd5b0af676290809ec3a53191dd81c7f70a4b28688a362182986f\n"
        "dffd6021bb2bd5b0af676290809ec3a53191dd81c7f70a4b28688a362182986f\n"
        "dffd6021bb2bd5b0af676290809ec3a53191dd81c7f70a4b28688a362182986f \"Hello, World!\"\n"
        "dffd6021bb2bd5b0af676290809ec3a53191dd81c7f70a4b28688a362182986f\n");
}

Test(sha256, test_sha256_cmd_file, .init = redirect_std)
{
    RUN_HASH_CMD("sha256", "tests/files/file1.txt");
    RUN_HASH_CMD("sha256", "-q", "tests/files/file1.txt");
    RUN_HASH_CMD("sha256", "-r", "tests/files/file1.txt");
    RUN_HASH_CMD("sha256", "-q", "-r", "tests/files/file1.txt");
    cr_assert_stdout_eq_str(
        "SHA256 (tests/files/file1.txt) = "
        "dffd6021bb2bd5b0af676290809ec3a53191dd81c7f70a4b28688a362182986f\n"
        "dffd6021bb2bd5b0af676290809ec3a53191dd81c7f70a4b28688a362182986f\n"
        "dffd6021bb2bd5b0af676290809ec3a53191dd81c7f70a4b28688a362182986f tests/files/file1.txt\n"
        "dffd6021bb2bd5b0af676290809ec3a53191dd81c7f70a4b28688a362182986f\n");
}

Test(sha256, test_sha256_cmd_file_s, .init = redirect_std)
{
    RUN_HASH_CMD("sha256", "-s", "Hello, World!", "tests/files/file2.txt");
    RUN_HASH_CMD("sha256", "-q", "-s", "Hello, World!", "tests/files/file2.txt");
    RUN_HASH_CMD("sha256", "-r", "-s", "Hello, World!", "tests/files/file2.txt");
    RUN_HASH_CMD("sha256", "-q", "-r", "-s", "Hello, World!", "tests/files/file2.txt");
    cr_assert_stdout_eq_str(
        "SHA256 (\"Hello, World!\") = "
        "dffd6021bb2bd5b0af676290809ec3a53191dd81c7f70a4b28688a362182986f\n"
        "SHA256 (tests/files/file2.txt) = "
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\n"
        "dffd6021bb2bd5b0af676290809ec3a53191dd81c7f70a4b28688a362182986f\n"
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\n"
        "dffd6021bb2bd5b0af676290809ec3a53191dd81c7f70a4b28688a362182986f \"Hello, World!\"\n"
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 tests/files/file2.txt\n"
        "dffd6021bb2bd5b0af676290809ec3a53191dd81c7f70a4b28688a362182986f\n"
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\n");
}

Test(sha256, test_sha256_cmd_files, .init = redirect_std)
{
    RUN_HASH_CMD("sha256",
                 "-q",
                 "tests/files/file1.txt",
                 "tests/files/file2.txt",
                 "tests/files/file3.txt",
                 "tests/files/file4.txt");
    cr_assert_stdout_eq_str("dffd6021bb2bd5b0af676290809ec3a53191dd81c7f70a4b28688a362182986f\n"
                            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\n"
                            "9520c61b2d868827dee48c207f0ee644767454e944ac90b530106642bdc36ff6\n"
                            "2944934a565b41d56efcfc8ccbc0180e7d8cea7cb60ed53d49e33be49a2133b3\n");
}

Test(sha256, test_sha256_cmd_errors, .init = redirect_std)
{
    RUN_HASH_CMD("sha256", "-s");
    RUN_HASH_CMD("sha256", "-l");
    RUN_HASH_CMD("sha256", "tests/files/unexisting_file", "tests/files/unexisting_file2");
    cr_assert_stderr_eq_str(
        "boxfort-worker: option requires an argument -- 's'\n"
        "boxfort-worker: invalid option -- 'l'\n"
        "boxfort-worker: sha256: tests/files/unexisting_file: No such file or directory\n"
        "boxfort-worker: sha256: tests/files/unexisting_file2: No such file or directory\n");
}

Test(whirlpool, test_whirlpool)
{
    TEST_WHIRLPOOL("",
                   "19fa61d75522a4669b44e39c1d2e1726c530232130d407f89afee0964997f7a73e83be698b288fe"
                   "bcf88e3e03c4f0757ea8964e59b63d93708b138cc42a66eb3");
    TEST_WHIRLPOOL("The quick brown fox jumps over the lazy dog",
                   "b97de512e91e3828b40d2b0fdce9ceb3c4a71f9bea8d88e75c4fa854df36725fd2b52eb6544edca"
                   "cd6f8beddfea403cb55ae31f03ad62a5ef54e42ee82c3fb35");
    TEST_WHIRLPOOL("Hello, World!",
                   "3d837c9ef7bb291bd1dcfc05d3004af2eeb8c631dd6a6c4ba35159b8889de4b1ec44076ce7a8f7b"
                   "fa497e4d9dcb7c29337173f78d06791f3c3d9e00cc6017f0b");
}

Test(whirlpool, test_whirlpool_cmd_stdin, .init = redirect_std)
{
    FILE* f_stdin = cr_get_redirected_stdin();
    fprintf(f_stdin, "Hello, World!");
    fclose(f_stdin);

    RUN_HASH_CMD("whirlpool");
    cr_assert_stdout_eq_str(
        " (stdin)= 3d837c9ef7bb291bd1dcfc05d3004af2eeb8c631dd6a6c4ba35159b8889de4b1ec44076ce7a8f7b"
        "fa497e4d9dcb7c29337173f78d06791f3c3d9e00cc6017f0b\n");
}

Test(whirlpool, test_whirlpool_cmd_stdin_p, .init = redirect_std)
{
    FILE* f_stdin = cr_get_redirected_stdin();
    fprintf(f_stdin, "Hello, World!");
    fclose(f_stdin);

    RUN_HASH_CMD("whirlpool", "-p");
    cr_assert_stdout_eq_str(
        " (\"Hello, World!\")= "
        "3d837c9ef7bb291bd1dcfc05d3004af2eeb8c631dd6a6c4ba35159b8889de4b1ec44076ce7a8f7b"
        "fa497e4d9dcb7c29337173f78d06791f3c3d9e00cc6017f0b\n");
}

Test(whirlpool, test_whirlpool_cmd_stdin_q, .init = redirect_std)
{
    FILE* f_stdin = cr_get_redirected_stdin();
    fprintf(f_stdin, "Hello, World!");
    fclose(f_stdin);

    RUN_HASH_CMD("whirlpool", "-q");
    cr_assert_stdout_eq_str(
        "3d837c9ef7bb291bd1dcfc05d3004af2eeb8c631dd6a6c4ba35159b8889de4b1ec44076ce7a8f7b"
        "fa497e4d9dcb7c29337173f78d06791f3c3d9e00cc6017f0b\n");
}

Test(whirlpool, test_whirlpool_cmd_s, .init = redirect_std)
{
    RUN_HASH_CMD("whirlpool", "-s", "Hello, World!");
    RUN_HASH_CMD("whirlpool", "-q", "-s", "Hello, World!");
    RUN_HASH_CMD("whirlpool", "-r", "-s", "Hello, World!");
    RUN_HASH_CMD("whirlpool", "-q", "-r", "-s", "Hello, World!");
    cr_assert_stdout_eq_str(
        "WHIRLPOOL (\"Hello, World!\") = "
        "3d837c9ef7bb291bd1dcfc05d3004af2eeb8c631dd6a6c4ba35159b8889de4b1ec44076ce7a8f7b"
        "fa497e4d9dcb7c29337173f78d06791f3c3d9e00cc6017f0b\n"
        "3d837c9ef7bb291bd1dcfc05d3004af2eeb8c631dd6a6c4ba35159b8889de4b1ec44076ce7a8f7b"
        "fa497e4d9dcb7c29337173f78d06791f3c3d9e00cc6017f0b\n"
        "3d837c9ef7bb291bd1dcfc05d3004af2eeb8c631dd6a6c4ba35159b8889de4b1ec44076ce7a8f7b"
        "fa497e4d9dcb7c29337173f78d06791f3c3d9e00cc6017f0b \"Hello, World!\"\n"
        "3d837c9ef7bb291bd1dcfc05d3004af2eeb8c631dd6a6c4ba35159b8889de4b1ec44076ce7a8f7b"
        "fa497e4d9dcb7c29337173f78d06791f3c3d9e00cc6017f0b\n");
}

Test(whirlpool, test_whirlpool_cmd_file, .init = redirect_std)
{
    RUN_HASH_CMD("whirlpool", "tests/files/file1.txt");
    RUN_HASH_CMD("whirlpool", "-q", "tests/files/file1.txt");
    RUN_HASH_CMD("whirlpool", "-r", "tests/files/file1.txt");
    RUN_HASH_CMD("whirlpool", "-q", "-r", "tests/files/file1.txt");
    cr_assert_stdout_eq_str(
        "WHIRLPOOL (tests/files/file1.txt) = "
        "3d837c9ef7bb291bd1dcfc05d3004af2eeb8c631dd6a6c4ba35159b8889de4b1ec44076ce7a8f7bfa497e4d9dc"
        "b7c29337173f78d06791f3c3d9e00cc6017f0b\n"
        "3d837c9ef7bb291bd1dcfc05d3004af2eeb8c631dd6a6c4ba35159b8889de4b1ec44076ce7a8f7bfa497e4d9dc"
        "b7c29337173f78d06791f3c3d9e00cc6017f0b\n"
        "3d837c9ef7bb291bd1dcfc05d3004af2eeb8c631dd6a6c4ba35159b8889de4b1ec44076ce7a8f7bfa497e4d9dc"
        "b7c29337173f78d06791f3c3d9e00cc6017f0b tests/files/file1.txt\n"
        "3d837c9ef7bb291bd1dcfc05d3004af2eeb8c631dd6a6c4ba35159b8889de4b1ec44076ce7a8f7bfa497e4d9dc"
        "b7c29337173f78d06791f3c3d9e00cc6017f0b\n");
}

Test(whirlpool, test_whirlpool_cmd_file_s, .init = redirect_std)
{
    RUN_HASH_CMD("whirlpool", "-s", "Hello, World!", "tests/files/file2.txt");
    RUN_HASH_CMD("whirlpool", "-q", "-s", "Hello, World!", "tests/files/file2.txt");
    RUN_HASH_CMD("whirlpool", "-r", "-s", "Hello, World!", "tests/files/file2.txt");
    RUN_HASH_CMD("whirlpool", "-q", "-r", "-s", "Hello, World!", "tests/files/file2.txt");
    cr_assert_stdout_eq_str(
        "WHIRLPOOL (\"Hello, World!\") = "
        "3d837c9ef7bb291bd1dcfc05d3004af2eeb8c631dd6a6c4ba35159b8889de4b1ec44076ce7a8f7bfa497e4d9dc"
        "b7c29337173f78d06791f3c3d9e00cc6017f0b\n"
        "WHIRLPOOL (tests/files/file2.txt) = "
        "19fa61d75522a4669b44e39c1d2e1726c530232130d407f89afee0964997f7a73e83be698b288febcf88e3e03c"
        "4f0757ea8964e59b63d93708b138cc42a66eb3\n"
        "3d837c9ef7bb291bd1dcfc05d3004af2eeb8c631dd6a6c4ba35159b8889de4b1ec44076ce7a8f7bfa497e4d9dc"
        "b7c29337173f78d06791f3c3d9e00cc6017f0b\n"
        "19fa61d75522a4669b44e39c1d2e1726c530232130d407f89afee0964997f7a73e83be698b288febcf88e3e03"
        "c4f0757ea8964e59b63d93708b138cc42a66eb3\n"
        "3d837c9ef7bb291bd1dcfc05d3004af2eeb8c631dd6a6c4ba35159b8889de4b1ec44076ce7a8f7bfa497e4d9dc"
        "b7c29337173f78d06791f3c3d9e00cc6017f0b \"Hello, World!\"\n"
        "19fa61d75522a4669b44e39c1d2e1726c530232130d407f89afee0964997f7a73e83be698b288febcf88e3e03"
        "c4f0757ea8964e59b63d93708b138cc42a66eb3 tests/files/file2.txt\n"
        "3d837c9ef7bb291bd1dcfc05d3004af2eeb8c631dd6a6c4ba35159b8889de4b1ec44076ce7a8f7bfa497e4d9dc"
        "b7c29337173f78d06791f3c3d9e00cc6017f0b\n"
        "19fa61d75522a4669b44e39c1d2e1726c530232130d407f89afee0964997f7a73e83be698b288febcf88e3e03"
        "c4f0757ea8964e59b63d93708b138cc42a66eb3\n");
}

Test(whirlpool, test_whirlpool_cmd_files, .init = redirect_std)
{
    RUN_HASH_CMD("whirlpool",
                 "-q",
                 "tests/files/file1.txt",
                 "tests/files/file2.txt",
                 "tests/files/file3.txt",
                 "tests/files/file4.txt");
    cr_assert_stdout_eq_str(
        "3d837c9ef7bb291bd1dcfc05d3004af2eeb8c631dd6a6c4ba35159b8889de4b1ec44076ce7a8f7bfa497e4d9dc"
        "b7c29337173f78d06791f3c3d9e00cc6017f0b\n"
        "19fa61d75522a4669b44e39c1d2e1726c530232130d407f89afee0964997f7a73e83be698b288febcf88e3e03"
        "c4f0757ea8964e59b63d93708b138cc42a66eb3\n"
        "440dd53177c25caa099396a86fcde996866ceb4764771f1edca5e2980e008da3bcf33d3edc85e5ebf5b3eae733"
        "5ac0d90599bdbeb71264fab8a7d26ee8517bf4\n"
        "1c2d95a7503ecaa9f523655117b40ebb90ef60c07a53191cc7248b251a7033f74af22df64e57fefaf6a8ed8a65"
        "4d13e70b90754150797ced0057fc5b326c07b1\n");
}

Test(whirlpool, test_whirlpool_cmd_errors, .init = redirect_std)
{
    RUN_HASH_CMD("whirlpool", "-s");
    RUN_HASH_CMD("whirlpool", "-l");
    RUN_HASH_CMD("whirlpool", "tests/files/unexisting_file", "tests/files/unexisting_file2");
    cr_assert_stderr_eq_str(
        "boxfort-worker: option requires an argument -- 's'\n"
        "boxfort-worker: invalid option -- 'l'\n"
        "boxfort-worker: whirlpool: tests/files/unexisting_file: No such file or directory\n"
        "boxfort-worker: whirlpool: tests/files/unexisting_file2: No such file or directory\n");
}
