#include "libft.h"
#include "printf/ft_printf.h"

int main()
{
	t_vector  *vector;

	vector = ft_vector_new(sizeof(int), 10);

	int a = 42;
	ft_vector_push_back(vector, &a);
	int b = 43;
	ft_vector_push_back(vector, &b);
	int c = 44;
	ft_vector_push_back(vector, &c);

	size_t	i = 0;
	while (i < vector->size)
	{
		ft_printf("%d\n", ((int *)vector->data)[i]);
		i++;
	}

	return (0);
}
