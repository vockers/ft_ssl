/* ************************************************************************** */
/*                                                                            */
/*                                                        ::::::::            */
/*   ft_strnjoin.c                                      :+:    :+:            */
/*                                                     +:+                    */
/*   By: vockers <vockers@student.codam.nl>           +#+                     */
/*                                                   +#+                      */
/*   Created: 2023/10/23 15:10:07 by vockers       #+#    #+#                 */
/*   Updated: 2023/10/23 15:10:07 by vockers       ########   odam.nl         */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

char	*ft_strnjoin(char const *s1, char const *s2, size_t s1_n, size_t s2_n)
{
	char	*new;
	int		i;

	if (!s1 || !s2)
		return (NULL);
	new = (char *)malloc(sizeof(char) * (s1_n + s2_n + 1));
	if (new == NULL)
		return (NULL);
	i = 0;
	while (s1_n--)
		new[i++] = *s1++;
	while (s2_n--)
		new[i++] = *s2++;
	new[i] = '\0';
	return (new);
}
