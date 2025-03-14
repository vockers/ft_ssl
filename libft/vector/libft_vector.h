#ifndef LIBFT_VECTOR_H
# define LIBFT_VECTOR_H

# include <stddef.h>

typedef struct s_vector
{
	void	*data;
	size_t	size;
	size_t	capacity;
	size_t	type_size;
}	t_vector;

t_vector  *ft_vector_new(size_t type_size, size_t initial_capacity);

int		  ft_vector_push_back(t_vector *vector, void *element);

#endif
