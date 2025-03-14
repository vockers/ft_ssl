/* ************************************************************************** */
/*                                                                            */
/*                                                        ::::::::            */
/*   ft_itoa_base.c                                     :+:    :+:            */
/*                                                     +:+                    */
/*   By: vockers <vockers@student.codam.nl>           +#+                     */
/*                                                   +#+                      */
/*   Created: 2023/10/02 14:45:01 by vockers       #+#    #+#                 */
/*   Updated: 2023/10/03 15:39:24 by vockers       ########   odam.nl         */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

char	*ft_itoa_base(int num, char *base)
{
	char	*tmp;
	char	*ret;

	if (num < 0)
	{
		tmp = ft_utoa_base(-num, base);
		ret = ft_strjoin("-", tmp);
		free(tmp);
	}
	else
		ret = ft_utoa_base(num, base);
	return (ret);
}
