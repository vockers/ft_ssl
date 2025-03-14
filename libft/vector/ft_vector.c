#include "libft_vector.h"
#include "libft.h"

t_vector	*ft_vector_new(size_t type_size, size_t initial_capacity)
{
	t_vector	*vector;

	vector = (t_vector *)malloc(sizeof(t_vector));
	if (vector == NULL)
		return (NULL);
	vector->type_size = type_size;
	vector->capacity = initial_capacity;
	vector->size = 0;
	vector->data = malloc(type_size * initial_capacity);
	if (vector->data == NULL)
	{
		free(vector);
		return (NULL);
	}
	return (vector);
}

int	ft_vector_push_back(t_vector *vector, void *element)
{
	void	*new_data;

	if (vector->size == vector->capacity)
	{
		new_data = malloc(vector->type_size * vector->capacity * 2);
		if (new_data == NULL)
			return (-1);
		ft_memcpy(new_data, vector->data, vector->type_size * vector->capacity);
		free(vector->data);
		vector->data = new_data;
		vector->capacity *= 2;
	}
	ft_memcpy((unsigned char*)vector->data + vector->size * vector->type_size, element, vector->type_size);
	vector->size++;
	return (0);
}
