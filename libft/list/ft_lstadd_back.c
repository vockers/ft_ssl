/* ************************************************************************** */
/*                                                                            */
/*                                                        ::::::::            */
/*   ft_lstadd_back.c                                   :+:    :+:            */
/*                                                     +:+                    */
/*   By: vockers <vockers@student.codam.nl>           +#+                     */
/*                                                   +#+                      */
/*   Created: 2023/10/02 14:44:56 by vockers       #+#    #+#                 */
/*   Updated: 2023/10/02 15:05:57 by vockers       ########   odam.nl         */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

void	ft_lstadd_back(t_list **lst, t_list *new)
{
	t_list	*l;

	if (lst == NULL)
		return ;
	l = ft_lstlast(*lst);
	if (l == NULL)
		*lst = new;
	else
		l->next = new;
}
