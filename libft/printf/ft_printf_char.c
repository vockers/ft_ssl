/* ************************************************************************** */
/*                                                                            */
/*                                                        ::::::::            */
/*   ft_printf_char.c                                   :+:    :+:            */
/*                                                     +:+                    */
/*   By: vockers <vockers@student.codam.nl>           +#+                     */
/*                                                   +#+                      */
/*   Created: 2023/10/26 11:18:08 by vockers       #+#    #+#                 */
/*   Updated: 2023/10/26 11:18:08 by vockers       ########   odam.nl         */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

char	*ft_convert_char(char c, t_format fmt)
{
	char	*ret;

	ret = ft_strdup(" ");
	ret = ft_apply_padding(ret, fmt.width, fmt.flags & FFLAG_MINUS);
	if (fmt.flags & FFLAG_MINUS)
		ret[0] = c;
	else
		ret[ft_strlen(ret) - 1] = c;
	return (ret);
}
