NAME        = ft_ssl
SRC_DIR     = ./src
INCLUDE_DIR = ./include
OBJ_DIR     = ./.obj

CC          = clang
CFLAGS      = -I$(INCLUDE_DIR) -Wall -Wextra -Werror
DEBUG_FLAGS = -MMD -MP -g -fsanitize=address

SRCS = $(wildcard $(SRC_DIR)/*.c) $(wildcard $(SRC_DIR)/*/*.c)
OBJS = $(patsubst $(SRC_DIR)/%.c,$(OBJ_DIR)/%.o,$(SRCS))

all: debug

debug: CFLAGS += $(DEBUG_FLAGS)
debug: $(NAME)

release: $(NAME)

$(NAME): $(OBJS)
	$(CC) $(CFLAGS) -o $(NAME) $(OBJS)

-include $(OBJS:.o=.d)

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -I$(INCLUDE_DIR) -c $< -o $@

clean:
	-rm -rf $(OBJ_DIR)

fclean: clean
	-rm -f $(NAME)

re: fclean all

.PHONY: all debug release clean fclean re

