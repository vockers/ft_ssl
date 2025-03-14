/* ************************************************************************** */
/*                                                                            */
/*                                                        ::::::::            */
/*   ft_utoa.c                                          :+:    :+:            */
/*                                                     +:+                    */
/*   By: vockers <vockers@student.codam.nl>           +#+                     */
/*                                                   +#+                      */
/*   Created: 2023/10/02 14:45:01 by vockers       #+#    #+#                 */
/*   Updated: 2023/10/03 15:39:24 by vockers       ########   odam.nl         */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

static int	count_digits(unsigned int num)
{
	int	count;

	if (num == 0)
		return (1);
	count = 0;
	while (num > 0)
	{
		count++;
		num /= 10;
	}
	return (count);
}

char	*ft_utoa(unsigned int num)
{
	char			*ret;
	int				len;

	len = count_digits(num);
	ret = (char *)ft_calloc(len + 1, sizeof(char));
	if (!ret)
		return (NULL);
	ret[len] = '\0';
	if (num == 0)
		ret[0] = '0';
	while (num > 0)
	{
		ret[--len] = (num % 10) + '0';
		num /= 10;
	}
	return (ret);
}
