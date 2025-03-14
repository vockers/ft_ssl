/* ************************************************************************** */
/*                                                                            */
/*                                                        ::::::::            */
/*   ft_ultoa_base.c                                    :+:    :+:            */
/*                                                     +:+                    */
/*   By: vockers <vockers@student.codam.nl>           +#+                     */
/*                                                   +#+                      */
/*   Created: 2023/10/23 13:12:21 by vockers       #+#    #+#                 */
/*   Updated: 2023/10/23 13:12:21 by vockers       ########   odam.nl         */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

static int	get_radix(char *base)
{
	int	radix;

	if (!base)
		return (0);
	radix = 0;
	while (base[radix])
		radix++;
	return (radix);
}

static int	count_digits(unsigned long num, int radix)
{
	int	count;

	if (num == 0)
		return (1);
	count = 0;
	while (num > 0)
	{
		count++;
		num /= radix;
	}
	return (count);
}

char	*ft_ultoa_base(unsigned long num, char *base)
{
	char			*ret;
	int				len;
	int				radix;

	radix = get_radix(base);
	if (radix <= 1)
		return (0);
	len = count_digits(num, radix);
	ret = (char *)ft_calloc(len + 1, sizeof(char));
	if (!ret)
		return (NULL);
	ret[len] = '\0';
	if (num == 0)
		ret[0] = base[0];
	while (num > 0)
	{
		ret[--len] = base[num % radix];
		num /= radix;
	}
	return (ret);
}
