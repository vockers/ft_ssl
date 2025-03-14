/* ************************************************************************** */
/*                                                                            */
/*                                                        ::::::::            */
/*   ft_putunbr_fd.c                                    :+:    :+:            */
/*                                                     +:+                    */
/*   By: vockers <vockers@student.codam.nl>           +#+                     */
/*                                                   +#+                      */
/*   Created: 2023/10/02 14:43:48 by vockers       #+#    #+#                 */
/*   Updated: 2023/10/03 16:20:59 by vockers       ########   odam.nl         */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

static int	putnbr_recursive(unsigned int num, char *buffer, int index)
{
	char	d;

	d = num % 10 + '0';
	num /= 10;
	if (num > 0)
		index = putnbr_recursive(num, buffer, index);
	buffer[index] = d;
	return (index + 1);
}

int	ft_putunbr_fd(unsigned int n, int fd)
{
	char	buffer[10];
	int		len;

	len = putnbr_recursive(n, buffer, 0);
	write(fd, buffer, len);
	return (len);
}
