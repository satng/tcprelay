/*
 * mem.c - memory pool
 *
 * Copyright (C) 2014, Xiaoxiao <i@xiaoxiao.im>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

#include <stdlib.h>
#include <assert.h>
#include "mem.h"

// // 内存池的块数
#define MEM_POOL_SIZE 32

static void *mem_pool = NULL;
static size_t block_size;
static size_t block_used;
static void *block_state[MEM_POOL_SIZE];

bool mem_init(size_t block)
{
	if (block <= 0)
	{
		return false;
	}
	mem_pool = (void *)malloc(block * MEM_POOL_SIZE);
	if (mem_pool == NULL)
	{
		return false;
	}
	block_size = block;
	block_used = 0;
	for (size_t i = 0; i < MEM_POOL_SIZE; i++)
	{
		block_state[i] = mem_pool + block_size * i;
	}
	return true;
}

void *mem_new(void)
{
	assert(mem_pool != NULL);

	if (block_used < MEM_POOL_SIZE)
	{
		return block_state[block_used++];
	}
	else
	{
		return malloc(block_size);
	}
}

void mem_delete(void *ptr)
{
	assert(mem_pool != NULL);

	if ((ptr < mem_pool) || (ptr > mem_pool + block_size * (MEM_POOL_SIZE - 1)))
	{
		free(ptr);
		return;
	}

	for (size_t i = 0; i < block_used; i++)
	{
		if (block_state[i] == ptr)
		{
			for (size_t j = i; j < block_used - 1; j++)
			{
				block_state[j] = block_state[j + 1];
			}
			block_state[--block_used] = ptr;
			return;
		}
	}
	return;
}
