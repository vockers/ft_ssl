/* ************************************************************************** */
/*                                                                            */
/*                                                        ::::::::            */
/*   ft_printf_int.c                                    :+:    :+:            */
/*                                                     +:+                    */
/*   By: vockers <vockers@student.codam.nl>           +#+                     */
/*                                                   +#+                      */
/*   Created: 2023/10/26 11:18:02 by vockers       #+#    #+#                 */
/*   Updated: 2023/10/26 11:18:02 by vockers       ########   odam.nl         */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

char	*ft_convert_int(int i, t_format fmt)
{
	char	*ret;

	if (i == 0 && fmt.precision == 0)
	{
		ret = ft_strdup("");
		ret = ft_apply_padding(ret, fmt.width, fmt.flags & FFLAG_MINUS);
		return (ret);
	}
	ret = ft_utoa(ft_abs(i));
	ret = ft_apply_precision(ret, fmt);
	if (fmt.flags & FFLAG_ZERO && ~ fmt.flags & FFLAG_MINUS
		&& fmt.precision == -1)
	{
		if (i < 0 || fmt.flags & FFLAG_SPACE || fmt.flags & FFLAG_PLUS)
			fmt.width -= 1;
		ret = ft_apply_zero_padding(ret, fmt.width);
		ret = ft_apply_sign(ret, i < 0, fmt);
	}
	else
	{
		ret = ft_apply_sign(ret, i < 0, fmt);
		ret = ft_apply_padding(ret, fmt.width, fmt.flags & FFLAG_MINUS);
	}
	return (ret);
}

char	*ft_convert_uint(unsigned int i, t_format fmt)
{
	char	*ret;

	if (i == 0 && fmt.precision == 0)
	{
		ret = ft_strdup("");
		ret = ft_apply_padding(ret, fmt.width, fmt.flags & FFLAG_MINUS);
		return (ret);
	}
	ret = ft_utoa(i);
	ret = ft_apply_precision(ret, fmt);
	if (fmt.flags & FFLAG_ZERO && ~ fmt.flags & FFLAG_MINUS
		&& fmt.precision == -1)
		ret = ft_apply_zero_padding(ret, fmt.width);
	else
		ret = ft_apply_padding(ret, fmt.width, fmt.flags & FFLAG_MINUS);
	return (ret);
}
