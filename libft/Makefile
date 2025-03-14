BUILD_DIR	= build
OBJ_DIR		= $(BUILD_DIR)/.obj
NAME		= $(BUILD_DIR)/libft.a
CC			= cc
CFLAGS		= -Wall -Wextra -Werror -I.

SRC			= \
	conversions/ft_abs.c \
	conversions/ft_atoi.c \
	conversions/ft_atol.c \
	conversions/ft_itoa.c \
	conversions/ft_utoa.c \
	conversions/ft_ultoa_base.c \
	conversions/ft_utoa_base.c \
	ctype/ft_isalnum.c \
	ctype/ft_isalpha.c \
	ctype/ft_isascii.c \
	ctype/ft_isdigit.c \
	ctype/ft_isprint.c \
	ctype/ft_isspace.c \
	ctype/ft_tolower.c \
	ctype/ft_toupper.c \
	dict/ft_dict.c \
	dict/ft_dict_utils.c \
	list/ft_lstadd_back.c \
	list/ft_lstadd_front.c \
	list/ft_lstclear.c \
	list/ft_lstdelone.c \
	list/ft_lstiter.c \
	list/ft_lstlast.c \
	list/ft_lstmap.c \
	list/ft_lstnew.c \
	list/ft_lstsize.c \
	io/ft_putchar_fd.c \
	io/ft_putendl_fd.c \
	io/ft_putnbr_fd.c \
	io/ft_putstr_fd.c \
	io/ft_putunbr_fd.c \
	io/get_next_line.c \
	memory/ft_bzero.c \
	memory/ft_calloc.c \
	memory/ft_free_strs.c \
	memory/ft_memchr.c \
	memory/ft_memcmp.c \
	memory/ft_memcpy.c \
	memory/ft_memmove.c \
	memory/ft_memset.c \
	printf/ft_printf.c \
	printf/ft_printf_convert.c \
	printf/ft_printf_flags.c \
	printf/ft_printf_parse.c \
	printf/ft_printf_char.c \
	printf/ft_printf_hex.c \
	printf/ft_printf_int.c \
	printf/ft_printf_ptr.c \
	printf/ft_printf_str.c \
	printf/ft_printf_utils.c \
	string/ft_split.c \
	string/ft_strchr.c \
	string/ft_strcmp.c \
	string/ft_strcpy.c \
	string/ft_strdup.c \
	string/ft_strisnum.c \
	string/ft_striteri.c \
	string/ft_strjoin.c \
	string/ft_strnjoin.c \
	string/ft_strlcat.c \
	string/ft_strlcpy.c \
	string/ft_strlen.c \
	string/ft_strmapi.c \
	string/ft_strmerge.c \
	string/ft_strncmp.c \
	string/ft_strndup.c \
	string/ft_strnlen.c \
	string/ft_strnstr.c \
	string/ft_strrchr.c \
	string/ft_strtrim.c \
	string/ft_substr.c \
	vector/ft_vector.c \

OBJS		= $(SRC:%.c=$(OBJ_DIR)/%.o)

all: $(NAME)

$(NAME): $(OBJS)
	ar -rcs $@ $^

$(OBJ_DIR)/%.o: %.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c -o $@ $^

clean:
	-rm -rf $(BUILD_DIR)

re: clean all

.PHONY: all clean re
