/* ************************************************************************** */
/*                                                                            */
/*                                                        ::::::::            */
/*   string_tests.c                                     :+:    :+:            */
/*                                                     +:+                    */
/*   By: vockers <vockers@student.codam.nl>           +#+                     */
/*                                                   +#+                      */
/*   Created: 2024/01/11 12:57:41 by vockers       #+#    #+#                 */
/*   Updated: 2024/01/11 12:57:41 by vockers       ########   odam.nl         */
/*                                                                            */
/* ************************************************************************** */

#include <assert.h>

#include "libft.h"

int	main(void)
{
	assert(ft_strisnum(NULL) == 0);
	assert(ft_strisnum("") == 0);
	assert(ft_strisnum("abc") == 0);
	assert(ft_strisnum("-") == 0);
	assert(ft_strisnum("--") == 0);
	assert(ft_strisnum("-+") == 0);
	assert(ft_strisnum("+") == 0);
	assert(ft_strisnum("++") == 0);
	assert(ft_strisnum("+-") == 0);
	assert(ft_strisnum("--0") == 0);
	assert(ft_strisnum("++0") == 0);
	assert(ft_strisnum("0") == 1);
	assert(ft_strisnum("010") == 1);
	assert(ft_strisnum("-010") == 1);
	assert(ft_strisnum("+125") == 1);
	ft_printf("All tests passed!\n");
}
