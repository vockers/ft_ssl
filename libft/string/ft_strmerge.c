/* ************************************************************************** */
/*                                                                            */
/*                                                        ::::::::            */
/*   ft_strmerge.c                                      :+:    :+:            */
/*                                                     +:+                    */
/*   By: vockers <vockers@student.codam.nl>           +#+                     */
/*                                                   +#+                      */
/*   Created: 2023/10/02 14:43:14 by vockers       #+#    #+#                 */
/*   Updated: 2023/10/03 14:57:48 by vockers       ########   odam.nl         */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

/*
 *	@brief Same as ft_strjoin but frees s1 and s2
 */
char	*ft_strmerge(char *s1, char *s2)
{
	char	*new;
	size_t	i;
	size_t	j;

	if (!s1 || !s2)
		return (NULL);
	new = (char *)malloc(sizeof(char) * (ft_strlen(s1) + ft_strlen(s2) + 1));
	if (new != NULL)
	{
		i = 0;
		j = 0;
		while (s1[j])
			new[i++] = s1[j++];
		j = 0;
		while (s2[j])
			new[i++] = s2[j++];
		new[i] = '\0';
	}
	free(s1);
	free(s2);
	return (new);
}
