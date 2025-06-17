NAME        = ft_ssl
SRC_DIR     = ./src
INCLUDE_DIR = ./include
OBJ_DIR     = ./.obj

TEST_NAME	 = test
TEST_OBJ_DIR = $(OBJ_DIR)/test

LIBFT_DIR	= ./libft
LIBFT		= ./libft/build/libft.a

CC          = clang
CFLAGS      = -I$(INCLUDE_DIR) -I$(LIBFT_DIR) -Wall -Wextra -Werror
LDFLAGS		= -L$(LIBFT_DIR)/build -lft
DEBUG_FLAGS = -MMD -MP -g -fsanitize=address
TEST_FLAGS  = -lcriterion

SRCS = asn1.c \
	   base64.c \
	   main.c \
	   math.c \
	   prime.c \
	   rand.c \
	   rsa.c \
	   md5.c \
	   sha256.c \
	   cli/cli.c \
	   cli/cmd_hash.c
OBJS = $(patsubst %.c,$(OBJ_DIR)/%.o,$(SRCS))

TEST_SRCS = base64.c \
			tests.c
TEST_OBJS = $(patsubst %.c,$(TEST_OBJ_DIR)/%.o,$(TEST_SRCS))

all: debug

debug: CFLAGS += $(DEBUG_FLAGS)
debug: $(NAME)

release: $(NAME)

test: $(LIBFT) $(TEST_OBJS)
	$(CC) $(CFLAGS) -o $(TEST_NAME) $(TEST_OBJS) $(LDFLAGS) $(TEST_FLAGS)
	./$(TEST_NAME)

$(NAME): $(LIBFT) $(OBJS)
	$(CC) $(CFLAGS) -o $(NAME) $(OBJS) $(LDFLAGS)

-include $(OBJS:.o=.d)

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -I$(INCLUDE_DIR) -c $< -o $@

$(TEST_OBJ_DIR)/%.o: $(SRC_DIR)/%.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -I$(INCLUDE_DIR) -c $< -o $@

$(LIBFT):
	$(MAKE) -C libft -f Makefile

clean:
	$(MAKE) -C $(LIBFT_DIR) clean
	-rm -rf $(OBJ_DIR)

fclean: clean
	-rm -f $(NAME)

re: fclean all

.PHONY: all debug release clean fclean re test

