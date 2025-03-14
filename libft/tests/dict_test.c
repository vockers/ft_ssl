/* ************************************************************************** */
/*                                                                            */
/*                                                        ::::::::            */
/*   dict_test.c                                        :+:    :+:            */
/*                                                     +:+                    */
/*   By: vockers <vockers@student.codam.nl>           +#+                     */
/*                                                   +#+                      */
/*   Created: 2023/12/17 17:58:22 by vockers       #+#    #+#                 */
/*   Updated: 2023/12/17 17:58:22 by vockers       ########   odam.nl         */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

#define TEST_SIZE 100

t_dict	*create_moc_dict(void)
{
	t_dict	*d;
	int		values[TEST_SIZE];
	long	i;
	char	*key;

	d = ft_dict_create();
	i = 0;
	while (i < TEST_SIZE)
	{
		values[i] = i * i;
		key = ft_strmerge(ft_strdup("key_"), ft_itoa(i));
		ft_dict_set(d, key, &values[i]);
		free(key);
		i++;
	}
	return (d);
}

int	main(void)
{
	t_dict	*d;
	int		val;

	d = create_moc_dict();
	val = *(int *)ft_dict_get(d, "key_5");
	printf("%d\n", val);
	val = *(int *)ft_dict_get(d, "key_8");
	printf("%d\n", val);
	val = *(int *)ft_dict_get(d, "key_15");
	printf("%d\n", val);
	ft_dict_free(d);
	return (0);
}
