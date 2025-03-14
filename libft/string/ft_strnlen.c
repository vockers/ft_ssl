/* ************************************************************************** */
/*                                                                            */
/*                                                        ::::::::            */
/*   ft_strnlen.c                                       :+:    :+:            */
/*                                                     +:+                    */
/*   By: vockers <vockers@student.codam.nl>           +#+                     */
/*                                                   +#+                      */
/*   Created: 2023/10/02 14:43:35 by vockers       #+#    #+#                 */
/*   Updated: 2023/10/03 15:23:33 by vockers       ########   odam.nl         */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

size_t	ft_strnlen(const char *str, size_t maxlen)
{
	const char	*s;

	s = str;
	while (*s && maxlen)
	{
		s++;
		maxlen--;
	}
	return (s - str);
}
