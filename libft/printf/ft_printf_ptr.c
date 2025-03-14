/* ************************************************************************** */
/*                                                                            */
/*                                                        ::::::::            */
/*   ft_printf_ptr.c                                    :+:    :+:            */
/*                                                     +:+                    */
/*   By: vockers <vockers@student.codam.nl>           +#+                     */
/*                                                   +#+                      */
/*   Created: 2023/10/26 11:17:59 by vockers       #+#    #+#                 */
/*   Updated: 2023/10/26 11:17:59 by vockers       ########   odam.nl         */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

char	*ft_convert_ptr(void *ptr, t_format fmt)
{
	char	*tmp;

	if (ptr == NULL)
	{
		ptr = ft_strdup("(nil)");
		ptr = ft_apply_padding(ptr, fmt.width, fmt.flags & FFLAG_MINUS);
		return (ptr);
	}
	ptr = ft_ultoa_base((unsigned long)ptr, "0123456789abcdef");
	ptr = ft_apply_precision(ptr, fmt);
	if (fmt.flags & FFLAG_ZERO && ~ fmt.flags & FFLAG_MINUS
		&& fmt.precision == -1)
	{
		fmt.width -= 2;
		tmp = ft_apply_zero_padding(ptr, fmt.width);
		ptr = ft_strjoin("0x", tmp);
		free(tmp);
	}
	else
	{
		tmp = ft_strjoin("0x", ptr);
		free(ptr);
		ptr = ft_apply_padding(tmp, fmt.width, fmt.flags & FFLAG_MINUS);
	}
	return (ptr);
}
