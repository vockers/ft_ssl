/* ************************************************************************** */
/*                                                                            */
/*                                                        ::::::::            */
/*   ft_free_strs.c                                     :+:    :+:            */
/*                                                     +:+                    */
/*   By: vockers <vockers@student.codam.nl>           +#+                     */
/*                                                   +#+                      */
/*   Created: 2023/11/03 14:15:42 by vockers       #+#    #+#                 */
/*   Updated: 2023/11/03 14:15:42 by vockers       ########   odam.nl         */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

void	ft_free_strs(char **strs)
{
	int	i;

	if (strs == NULL)
		return ;
	i = 0;
	while (strs[i])
	{
		free(strs[i]);
		i++;
	}
	free(strs);
}
