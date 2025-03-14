NAME        = ft_ssl
SRC_DIR     = ./src
INCLUDE_DIR = ./include
OBJ_DIR     = ./.obj

LIBFT_DIR	= ./libft
LIBFT		= ./libft/build/libft.a

CC          = clang
CFLAGS      = -I$(INCLUDE_DIR) -I$(LIBFT_DIR) # -Wall -Wextra -Werror
LDFLAGS		= -L$(LIBFT_DIR)/build -lft
DEBUG_FLAGS = -MMD -MP -g -fsanitize=address


SRCS = $(wildcard $(SRC_DIR)/*.c) $(wildcard $(SRC_DIR)/*/*.c)
OBJS = $(patsubst $(SRC_DIR)/%.c,$(OBJ_DIR)/%.o,$(SRCS))

all: debug

debug: CFLAGS += $(DEBUG_FLAGS)
debug: $(NAME)

release: $(NAME)

$(NAME): $(LIBFT) $(OBJS)
	$(CC) $(CFLAGS) -o $(NAME) $(OBJS) $(LDFLAGS)

-include $(OBJS:.o=.d)

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c
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

.PHONY: all debug release clean fclean re

